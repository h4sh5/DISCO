/***************************************************************************

    disco.c - Disco main c file

    Date: 06.12.2003
    Ver : 1.2

    Disco: The passive ip discovery and fingerprinting tool

    Copyright (c) 2003 by Preston Wood
    All rights reserved.

    Author(s): Preston Wood  <p@altmode.com>

/***************************************************************************

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
  OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
  THE AUTHOR, OR ANY OTHER CONTRIBUTORS BE LIABLE FOR ANY CLAIM,
  DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
  OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
  OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

***************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include "./disco.h"
/* disco.c */

int loop = 1;
u_long ip = 0;
int synack=0,verbose=0,fp_cand=0,found=0,unique_ip=0,totpacket_fp=0,totfp=0,ack=0,fingerprint=0,allip=0;
char found_os[255];
char optstr[60]="";
uint32_t srcip;
struct fingerprints loadedfp[MAXFP];
struct fingerprints packet_fp;
struct table_entry *fhash_table[HASH_TABLE_SIZE];
struct table_entry *ihash_table[HASH_TABLE_SIZE];
struct table_entry *ahash_table[HASH_TABLE_SIZE];
struct iphdr *ip_h;
struct tcphdr *tcp_h;


int main(int argc, char **argv)
{
    int c=0;         
    int totfp=0;
    pcap_t *p;
    char *device = NULL, *rule = NULL;
    char *foundip;
    char *dstip;
    char *logfile = NULL;

    char *pipearg = NULL;     // -p argument as a C string
    char *pretext = NULL;     // -P argument as a C string
    char *args[MAX_NUM_ARGS]; // Arguments for pipe output

    char *saved_file = NULL;
    char *timestamp = NULL;
    u_char *packet;
    int print_ip=1,ethmode=0,discover=0,itime=0,disp_time=0,only_syn=0,iphlen=0,use_file=0;
    struct pcap_pkthdr h;
    struct pcap_stat ps;
    struct in_addr *paaddr;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program filter_code;
    bpf_u_int32 local_net, netmask;
    FILE *outfile;
    time_t stime;

    while ((c = getopt(argc, argv, "evDAfNSs:i:r:o:p:P:uht")) != -1)

    {
            switch (c)
            {
		     case 'e':
		     	ethmode = 1;
			break;
		     case 'v':
		        verbose = 1;
			break;
		     case 'D':
		        discover = 1;
			break;
		     case 'A':
		     	ack = 1;
			break;
		     case 'f':
                        totfp = load_fingerprints();
                        fingerprint = 1;
                        break;
                     case 'N':
                        print_ip = 0;
                        break;
                     case 'S':
                        only_syn = 1;
                        break;
		     case 's':
		     	saved_file = optarg;
			use_file = 1;
			break;
                     case 'i':
                        device = optarg;
                        break;
                     case 'r':
                        rule = optarg;
                        break;
                     case 'u':
                        unique_ip = 1;
                        break;
                     case 'o':
                        logfile = optarg;
                        break;
		     case 'p':
                        pipearg = optarg;
                        break;
                     case 'P':
                        pretext = optarg;
                        break;
                     case 'h':
                        usage("Options");
                        break;
		     case 't':
			disp_time = 1;
//			timer = time(NULL);
			break;
                     default:
                        usage("Bad Option");
            }
            if ( rule == NULL )
            {
                rule = "ip";
            }
    }

    if ( c==0 )
    {
        usage("Need Option");
    }

    printf("Disco v1.2\n");

    /* If the -p option was set, parse its argument into an
     * argv-style array */

    if (pipearg != NULL)
    {
        if (!parse(pipearg, args))
        {
            fprintf(stderr, "Could not parse -p argument\n");
            exit(EXIT_FAILURE);

        } // if (parsing failed)

    } // if (parsing pipearg)

    /* If no device is specified error out */

    if (device == NULL)
    {
        device = pcap_lookupdev(errbuf);
        if (device == NULL)
        {
            fprintf(stderr, "pcap_lookupdev() failed: %s\n", errbuf);
        }
    }

    if (saved_file == NULL)
    {

    	/* Open the ethernet interface for packet capture */

    	p = pcap_open_live(device, SNAPLEN, PROMISC, TIMEOUT, errbuf);
    	if (p == NULL)
    	{
        	fprintf(stderr, "pcap_open_live() failed: %s\n", errbuf);
        	exit(EXIT_FAILURE);
    	}


	if (ethmode == 0)
	{
		/* Set BPF filter only looking at IP packets */
		if (pcap_lookupnet(device, &local_net, &netmask, errbuf) == -1)
    		{
        		fprintf(stderr, "pcap_lookupnet() failed: %s\n", errbuf);
        		pcap_close(p);
        		exit(EXIT_FAILURE);
    		}
	}

    }
    else
    {
    	p = pcap_open_offline(saved_file, errbuf);
    	if (p == NULL)
    	{
    		fprintf(stderr, "pcap_open_offline() failed: %s\n", errbuf);
		exit(EXIT_FAILURE);
    	}
    }

    /* Compile rule expression into a program */

    if (pcap_compile(p, &filter_code, rule, 1, netmask) == -1)
    {
        fprintf(stderr, "pcap_compile() failed: %s\n", pcap_geterr(p));
        pcap_close(p);
        exit(EXIT_FAILURE);
    }

    /* Load the compiled filter in the packet capture device */

    if (pcap_setfilter(p, &filter_code) == -1)
    {
        fprintf(stderr, "pcap_setfilter() failed: %s\n", pcap_geterr(p));
        pcap_close(p);
        exit(EXIT_FAILURE);
    }

    /* Check the link to make sure it is ethernet */

    if (pcap_datalink(p) != DLT_EN10MB)
    {
        fprintf(stderr, "Disco only works on ethernet networks\n");
        pcap_close(p);
        exit(EXIT_FAILURE);
    }

    /* Gather captured packet stats before we exit */

    if (catch_sig(SIGINT, cleanup) == -1)
    {
        fprintf(stderr, "Can't catch the signal\n");
        pcap_close(p);
        exit(EXIT_FAILURE);
    }

    ht_init_table(ihash_table);
    outfile = fopen(logfile,"w");

    /* Start looping through packets ctrl-c to exit */

    for ( ht_init_table(fhash_table); loop;)
    {
        packet = (u_char *)pcap_next(p, &h);
        if (packet == NULL)
        {
		if ( use_file == 1 )
		{
			exit(EXIT_SUCCESS);
		}
		else
		{
            		continue;
		}
        }

        /* Parse IP Hdr to check */
        ip_h = (struct iphdr *) (packet + 14);
        iphlen = ((ip_h->ihl*4));

        srcip = (ntohl(ip_h->saddr)); //Convert src network ip to host order for easier handling

        if (discover == 1)
        {
            if (packet_to_check(srcip, ihash_table))  //Pass src to check for dupes if none print output
            {
                if ( logfile != NULL )
                {
		    if ( disp_time == 0 )
		    {
                    	fprintf(outfile, "%s\n", iprintf(packet + 26));
		    }
		    else
		    {
		    	stime = time(NULL);
			timestamp = asctime(localtime(&stime));
			if ( timestamp[strlen(timestamp)-1]=='\n')
				timestamp[strlen(timestamp)-1] = 0;
			fprintf(outfile, "%s,%s\n", timestamp, iprintf(packet + 26));
		    }
                }
                if ( print_ip == 1 )
                {
                    if ( pipearg != NULL )
                        pipe_out(pretext, iprintf(packet + 26), args);
                    else
                        printf("%s\n", iprintf(packet + 26));

                }
            }
        }

        if ( unique_ip==1 && only_syn == 1) // If fingerprint flag and unique flag is set
        {
          if (ip_h->protocol==6)
          {
            switch (ip_h->ihl)
            {
              case 5:     //IP Header length of 20 - no options
                tcp_h = (struct tcphdr *) (packet + (iphlen+14));
                break;
              default:    //Parse through IP options
                tcp_h = (struct tcphdr *)(packet+14+(iphlen<<2));
                break;
            }

            if (tcp_h->syn==1 && tcp_h->ack==0) // Looking for just SYN packets
            {
                synack = 0;
                if (packet_to_check(srcip, fhash_table))
                {
                    fingerprint_packet(packet);

                    if ( found==1 ) //If fingerprint match is found for packet output IP and OS
                    {
                        foundip = iprintf(packet + 26);
                        if ( logfile != NULL )
                        {
			    if ( disp_time == 0 )
			    {
                            	fprintf(outfile, "%s,%s,S\n", foundip, found_os);
			    }
			    else
			    {
			    	stime = time(NULL);
				timestamp = asctime(localtime(&stime));
				if ( timestamp[strlen(timestamp)-1]=='\n')
					timestamp[strlen(timestamp)-1] = 0;
				if ( verbose == 1)
				{
					fprintf(outfile, "%s,%s,%s,S,%s\n", timestamp, foundip, found_os, optstr);
				}
				else
				{
					fprintf(outfile, "%s,%s,%s,S\n", timestamp, foundip, found_os);
				}
			    }
                        }
                        if ( print_ip == 1 )
                        {
                            printf("%s: %s (S)\n", foundip, found_os);
                        }
                        strcpy (found_os, "");
                        totpacket_fp++; //Increment total IP counter
                    }
                    if ( found==0 )  //If no fingerprint match is found for packet output IP and fingerprint
                    {
                        foundip = iprintf(packet + 26);
                        if ( logfile != NULL )
                        {
			    if ( disp_time == 0 )
			    {
                            	fprintf(outfile, "%s,%d:%d:%d:%d:%d:%d:%d:%d,S\n",foundip,packet_fp.win, packet_fp.ttl, packet_fp.mss, packet_fp.df, packet_fp.wscale, packet_fp.sackok, packet_fp.nop, packet_fp.psize);
			    }
			    else
			    {
			    	stime = time(NULL);
				timestamp = asctime(localtime(&stime));
				if ( timestamp[strlen(timestamp)-1]=='\n')
					timestamp[strlen(timestamp)-1] = 0;
				if ( verbose == 1)
				{

                            		fprintf(outfile, "%s,%s,%d:%d:%d:%d:%d:%d:%d:%d,S,%s\n",timestamp, foundip,packet_fp.win, packet_fp.ttl, packet_fp.mss, packet_fp.df, packet_fp.wscale, packet_fp.sackok, packet_fp.nop, packet_fp.psize,optstr);
				}
				else
				{
                            		fprintf(outfile, "%s,%s,%d:%d:%d:%d:%d:%d:%d:%d,S\n",timestamp, foundip,packet_fp.win, packet_fp.ttl, packet_fp.mss, packet_fp.df, packet_fp.wscale, packet_fp.sackok, packet_fp.nop, packet_fp.psize);
				}
			    }
                        }
                        if ( print_ip == 1 )
                        {
                            printf("%s: %d:%d:%d:%d:%d:%d:%d:%d:%s\n",foundip,packet_fp.win, packet_fp.ttl, packet_fp.mss, packet_fp.df, packet_fp.wscale, packet_fp.sackok, packet_fp.nop, packet_fp.psize, packet_fp.packet_type);
                        }
                        totpacket_fp++;
                    }

                    /* Reset globals for next packet to check */

                    fp_cand = 0;
                    found = 0;
                }
            }
          }
        }
        else if ( unique_ip==0 && only_syn == 1) //If fingerprint flag is set and unique flag is not
        {
            if (ip_h->protocol==6)
            {
                switch (ip_h->ihl)
                {
                    case 5:     //IP Header length of 20 - no options
                      tcp_h = (struct tcphdr *) (packet + (iphlen+14));
                      //tcp_opt = (struct tcphdr *) (packet + iphlen);
                      break;
                    default:    //Parse through IP options
                      tcp_h = (struct tcphdr *)(packet+14+(iphlen<<2));
                      break;
                }
                if (tcp_h->syn==1 && tcp_h->ack==0)
                {
                    synack = 0;
                    fingerprint_packet(packet);
                    if ( found==1 )
                    {
                        foundip = iprintf(packet + 26);
                        if ( logfile != NULL )
                        {
			    if ( disp_time == 0 )
			    {
                            	fprintf(outfile, "%s,%s,S\n",foundip, found_os);
			    }
			    else
			    {
			    	stime = time(NULL);
				timestamp = asctime(localtime(&stime));
				if ( timestamp[strlen(timestamp)-1]=='\n')
					timestamp[strlen(timestamp)-1] = 0;
				if ( verbose == 1 )
				{
				fprintf(outfile, "%s,%s,%s,S,%s\n", timestamp, foundip, found_os,optstr);
				}
				else
				{
					fprintf(outfile, "%s,%s,%s,S\n", timestamp, foundip, found_os);
				}
			    }
                        }
                        if ( print_ip == 1 )
                        {
                            printf("%s: %s (S)\n", foundip, found_os);
                        }
                        strcpy (found_os, "");
                        totpacket_fp++;
                    }
                    if ( found==0 )
                    {
                        foundip = iprintf(packet + 26);
                        if ( logfile != NULL )
                        {
			    if ( disp_time == 0 )
			    {
                           	fprintf(outfile, "%s,%d:%d:%d:%d:%d:%d:%d:%d,S\n",foundip,packet_fp.win, packet_fp.ttl, packet_fp.mss, packet_fp.df, packet_fp.wscale, packet_fp.sackok, packet_fp.nop, packet_fp.psize);
			    }
			    else
			    {
			    	stime = time(NULL);
			    	timestamp = asctime(localtime(&stime));
			    	if ( timestamp[strlen(timestamp)-1]=='\n')
					timestamp[strlen(timestamp)-1] = 0;
				if ( verbose == 1 )
				{
fprintf(outfile,"%s,%s,%d:%d:%d:%d:%d:%d:%d:%d,S,%s\n",timestamp,foundip,packet_fp.win,packet_fp.ttl, packet_fp.mss, packet_fp.df, packet_fp.wscale, packet_fp.sackok, packet_fp.nop, packet_fp.psize,optstr);
				}
				else
				{
                         		fprintf(outfile, "%s,%s,%d:%d:%d:%d:%d:%d:%d:%d,S\n",timestamp,foundip,packet_fp.win, packet_fp.ttl, packet_fp.mss, packet_fp.df, packet_fp.wscale, packet_fp.sackok, packet_fp.nop, packet_fp.psize);
				}
			    }
                        }
                        if ( print_ip == 1 )
                        {
                            printf("%s: %d:%d:%d:%d:%d:%d:%d:%d:%s\n",foundip,packet_fp.win, packet_fp.ttl, packet_fp.mss, packet_fp.df, packet_fp.wscale, packet_fp.sackok, packet_fp.nop, packet_fp.psize, packet_fp.packet_type);
                        }
                        totpacket_fp++;
                    }

                    /* Reset globals for next packet to check */

                    fp_cand = 0;
                    found = 0;
                }
            }
        }

	if ( unique_ip==1 && ack==1) // If fingerprint flag and unique flag is set
        {
          if (ip_h->protocol==6)
          {
            switch (ip_h->ihl)
            {
              case 5:     //IP Header length of 20 - no options
                tcp_h = (struct tcphdr *) (packet + (iphlen+14));
                break;
              default:    //Parse through IP options
                tcp_h = (struct tcphdr *)(packet+14+(iphlen<<2));
                break;
            }

            if (tcp_h->syn==1 && tcp_h->ack==1) // Looking for SYNACK packets
            {
                synack = 1;
                if (packet_to_check(srcip, ahash_table))
                {
                    fingerprint_packet(packet);

                    if ( found==1 ) //If fingerprint match is found for packet output IP and OS
                    {
                        foundip = iprintf(packet + 26);
                        if ( logfile != NULL )
                        {
			    if ( disp_time == 0 )
			    {
                            	fprintf(outfile, "%s,%s,A\n", foundip, found_os);
			    }
			    else
			    {
			    	stime = time(NULL);
				timestamp = asctime(localtime(&stime));
				if ( timestamp[strlen(timestamp)-1]=='\n')
					timestamp[strlen(timestamp)-1] = 0;
				if ( verbose == 1)
				{
				fprintf(outfile, "%s,%s,%s,A,%s\n", timestamp, foundip, found_os,optstr);
				}
				else
				{
					fprintf(outfile, "%s,%s,%s,A\n", timestamp, foundip, found_os);
				}
			    }
                        }
                        if ( print_ip == 1 )
                        {
                            printf("%s: %s (A)\n", foundip, found_os);
                        }
                        strcpy (found_os, "");
                        totpacket_fp++; //Increment total IP counter
                    }
                    if ( found==0 )  //If no fingerprint match is found for packet output IP and fingerprint
                    {
                        foundip = iprintf(packet + 26);
                        if ( logfile != NULL )
                        {
			    if ( disp_time == 0 )
			    {
                            	fprintf(outfile, "%s,%d:%d:%d:%d:%d:%d:%d:%d,A\n",foundip,packet_fp.win, packet_fp.ttl, packet_fp.mss, packet_fp.df, packet_fp.wscale, packet_fp.sackok, packet_fp.nop, packet_fp.psize);
			    }
			    else
			    {
			    	stime = time(NULL);
				timestamp = asctime(localtime(&stime));
				if ( timestamp[strlen(timestamp)-1]=='\n')
					timestamp[strlen(timestamp)-1] = 0;
				if ( verbose == 1)
				{
                            	fprintf(outfile,"%s,%s,%d:%d:%d:%d:%d:%d:%d:%d,A,%s\n",timestamp, foundip,packet_fp.win, packet_fp.ttl, packet_fp.mss, packet_fp.df, packet_fp.wscale, packet_fp.sackok, packet_fp.nop, packet_fp.psize,optstr);
				}
				else
				{
                            		fprintf(outfile, "%s,%s,%d:%d:%d:%d:%d:%d:%d:%d,A\n",timestamp, foundip,packet_fp.win, packet_fp.ttl, packet_fp.mss, packet_fp.df, packet_fp.wscale, packet_fp.sackok, packet_fp.nop, packet_fp.psize);
				}
			    }
                        }
                        if ( print_ip == 1 )
                        {
                            printf("%s: %d:%d:%d:%d:%d:%d:%d:%d:%s\n",foundip,packet_fp.win, packet_fp.ttl, packet_fp.mss, packet_fp.df, packet_fp.wscale, packet_fp.sackok, packet_fp.nop, packet_fp.psize, packet_fp.packet_type);
                        }
                        totpacket_fp++;
                    }

                    /* Reset globals for next packet to check */

                    fp_cand = 0;
                    found = 0;
                }
            }
          }
        }
        else if ( unique_ip==0 && ack==1) //If fingerprint flag is set and unique flag is not
        {
            if (ip_h->protocol==6)
            {
                switch (ip_h->ihl)
                {
                    case 5:     //IP Header length of 20 - no options
                      tcp_h = (struct tcphdr *) (packet + (iphlen+14));
                      //tcp_opt = (struct tcphdr *) (packet + iphlen);
                      break;
                    default:    //Parse through IP options
                      tcp_h = (struct tcphdr *)(packet+14+(iphlen<<2));
                      break;
                }
                if (tcp_h->syn==1 && tcp_h->ack==1)
                {
                    synack = 1;
                    fingerprint_packet(packet);
                    if ( found==1 )
                    {
                        foundip = iprintf(packet + 26);
                        if ( logfile != NULL )
                        {
			    if ( disp_time == 0 )
			    {
                            	fprintf(outfile, "%s,%s,A\n",foundip, found_os);
			    }
			    else
			    {
			    	stime = time(NULL);
				timestamp = asctime(localtime(&stime));
				if ( timestamp[strlen(timestamp)-1]=='\n')
					timestamp[strlen(timestamp)-1] = 0;
				if ( verbose == 1 )
				{
					fprintf(outfile, "%s,%s,%s,A,%s\n", timestamp, foundip, found_os,optstr);
				}
				else
				{
					fprintf(outfile, "%s,%s,%s,A\n", timestamp, foundip, found_os);
				}
			    }
                        }
                        if ( print_ip == 1 )
                        {
                            printf("%s: %s (A)\n", foundip, found_os);
                        }
                        strcpy (found_os, "");
                        totpacket_fp++;
                    }
                    if ( found==0 )
                    {
                        foundip = iprintf(packet + 26);
                        if ( logfile != NULL )
                        {
			    if ( disp_time == 0 )
			    {
                           	fprintf(outfile, "%s,%d:%d:%d:%d:%d:%d:%d:%d,A\n",foundip,packet_fp.win, packet_fp.ttl, packet_fp.mss, packet_fp.df, packet_fp.wscale, packet_fp.sackok, packet_fp.nop, packet_fp.psize);
			    }
			    else
			    {
			    	stime = time(NULL);
			    	timestamp = asctime(localtime(&stime));
			    	if ( timestamp[strlen(timestamp)-1]=='\n')
					timestamp[strlen(timestamp)-1] = 0;
				if ( verbose == 1 )
				{
fprintf(outfile,"%s,%s,%d:%d:%d:%d:%d:%d:%d:%d,A,%s\n",timestamp,foundip,packet_fp.win, packet_fp.ttl, packet_fp.mss, packet_fp.df, packet_fp.wscale, packet_fp.sackok, packet_fp.nop, packet_fp.psize,optstr);
				}
				else
				{
                         		fprintf(outfile, "%s,%s,%d:%d:%d:%d:%d:%d:%d:%d,A\n",timestamp,foundip,packet_fp.win, packet_fp.ttl, packet_fp.mss, packet_fp.df, packet_fp.wscale, packet_fp.sackok, packet_fp.nop, packet_fp.psize);
				}
			    }
                        }
                        if ( print_ip == 1 )
                        {
                            printf("%s: %d:%d:%d:%d:%d:%d:%d:%d:%s\n",foundip,packet_fp.win, packet_fp.ttl, packet_fp.mss, packet_fp.df, packet_fp.wscale, packet_fp.sackok, packet_fp.nop, packet_fp.psize, packet_fp.packet_type);
                        }
                        totpacket_fp++;
                    }

                    /* Reset globals for next packet to check */

                    fp_cand = 0;
                    found = 0;
                }
            }
        }



    }

    /* crtl-c exit */

    if (pcap_stats(p, &ps) == -1)
    {
        fprintf(stderr, "pcap_stats() failed: %s\n", pcap_geterr(p));
    }
    else
    {
        /* If user exits display some packet statistics */

        printf("\nPackets received by Disco:\t%6d\n"
                 "Packets dropped by Disco:\t%6d\n"
                 "Unique IP addresses received by Disco:\t%6ld\n",
                 ps.ps_recv, ps.ps_drop, ip);
        printf("Total IP fingerprinted by Disco: \t%6d\n", totpacket_fp);
    }
    pcap_close(p);
    return (EXIT_SUCCESS);
}


/* Routine to print hex ip in decimal */

char * iprintf(u_char *address)
{
    static char ip_addr[17];

    sprintf(ip_addr, "%3d.%3d.%3d.%3d", (address[0]&255), (address[1]&255), (address[2]&255), (address[3]&255));
    return (ip_addr);
}

/* Check packet source ip for uniqueness */

int packet_to_check(uint32_t src_ip, struct table_entry **hash_table)
{
    uint32_t n;

    n = packet_hash(src_ip);  //Function to hash src ip from packet

    allip++;  //Increment packet statistic counter

    if (hash_table[n]) //If entry exists in hash table
    {
        if (!packet_dup_check(src_ip, hash_table, n)) //Check hash table for src ip
        {
            if (packet_add_entry(src_ip, hash_table, n)) //If no dupes are found add src ip to hash table
            {
                ip++;
                return(1);
            }
        }
        else  // If src ip dupe is found exit
        {
            return(0);
        }
    }
    else
    {
        if (packet_add_entry(src_ip, hash_table, n))
        {
            ip++;
            return(1);
        }
    }
    return (0);
}

/* Hash source ip into unique number */

uint32_t packet_hash(uint32_t src_ip)
{
    return (src_ip %= HASH_TABLE_SIZE); //Return remainder (Modulus) from src ip divided by hash table size     
}

/* Check source ip for dups in the hash table */

int packet_dup_check(uint32_t src_ip, struct table_entry **hash_table, uint32_t loc)
{
    struct table_entry *p;
    
    for (p = hash_table[loc]; p; p = p->next)
    {
        if (p->uip == src_ip)
        {
            return (1);
        }
    }
    return (0);
}

/* If packet isn't a dup add to hash table */

int packet_add_entry(uint32_t src_ip, struct table_entry **hash_table, uint32_t loc) //Add src ip to hash table
{
    struct table_entry *p;
    
    if (hash_table[loc] == NULL)
    {
        hash_table[loc] = malloc(sizeof(struct table_entry));
        if (hash_table[loc] == NULL)
        {
            return(0);
        }
        hash_table[loc]->uip = src_ip;
        hash_table[loc]->next = NULL;
        return (1);
    }
    else
    {
        for (p = hash_table[loc]; p->next; p = p->next);
        p->next = malloc(sizeof(struct table_entry));
        if (p->next == NULL)
        {
            return (0);
        }

        p = p->next;

        p->uip = src_ip;
        p->next = NULL;
    }
    return (1);
}

/* Routine to fingerprint the SYN packet */

char fingerprint_packet(u_char *packet)
{
    int i=0,j=0;
    int testi=0;
    char teststr[6];
    int count=0;
    int opt=0;
    int fullopt=0;
    int iphlen=0;
    int optlen=0;
    int packettype_cmp;
    int ttlcount;
    int wscale_exists = 0;
//    char optstrg;
    struct iphdr *ip_h;
    struct tcphdr *tcp_h;
    struct ethhdr *ether;

    void* opt_ptr;

    char src_ip[20], dest_ip[20];

    ip_h = (struct iphdr *) (packet + 14);


    iphlen = ((ip_h->ihl*4));

       switch (ip_h->ihl)
        {
            case 5:     //IP Header length of 20 - no options
              tcp_h = (struct tcphdr *) (packet + (iphlen+14));
              break;
            default:    //Parse through IP options
              tcp_h = (struct tcphdr *)(packet+14+(iphlen<<2));
              break;
        }
                fp_cand = 1;
                packet_fp.win = ntohs(tcp_h->window);
                packet_fp.ttl = ip_h->ttl;
                packet_fp.sackok = 0;
                packet_fp.nop = 0;
                packet_fp.psize = ntohs(ip_h->tot_len);
                if (ip_h->frag_off==64)
                {
                  packet_fp.df = 1;
                }
                else
                {
                  packet_fp.df = 0;
                }
		if ( synack == 0 )
		{
//		  packet_fp.packet_type = (char) malloc(strlen (SYNCHAR)+1);
		  strcpy (packet_fp.packet_type, SYNCHAR);
		}
		if ( synack == 1 )
		{
//		  packet_fp.packet_type = (char) malloc(strlen (SYNACKCHAR)+1);
		  strcpy (packet_fp.packet_type, SYNACKCHAR);
		}
                opt_ptr=(void*)tcp_h+sizeof(struct tcphdr);
                optlen = (ntohs(ip_h->tot_len))-(sizeof(struct iphdr))-(sizeof(struct tcphdr));
		if ( verbose == 1 )
		{
			strcpy(teststr, "       ");
			testi = sprintf(teststr, "%d", packet_fp.win);
			strcpy(optstr, "WIN-");
			strcat(optstr, teststr);
			strcat(optstr, "|");
			testi = sprintf(teststr, "%d", packet_fp.df);
			strcat(optstr, "DF-");
			strcat(optstr, teststr);
			strcat(optstr, "|");
		}
                while ( i < optlen )
                {
                  opt=(int)(*(u_char*)(opt_ptr+i));
                  switch(opt)
                  {
                    case TCPOPT_MAXSEG:
                    {
                      packet_fp.mss = EXTRACT_16BITS(opt_ptr+2);
                      i+=3;
		      if ( verbose == 1 )
		      {
		      	testi = sprintf(teststr, "%d", packet_fp.mss);
		      	strcat(optstr, "MSS-");
		      	strcat(optstr, teststr);
		      	strcat(optstr, "|");
		      }
                      break;
                    }
                    case TCPOPT_SACKOK:
                    {
                      packet_fp.sackok = 1;
                      i+=1;
		      if ( verbose == 1 )
		      {
		      	strcat(optstr, "SACKOK");
		      	strcat(optstr, "|");
		      }
                      break;
                    }
                    case TCPOPT_NOP:
                    {
                      packet_fp.nop = 1;
		      if ( verbose == 1)
		      {
		      	strcat(optstr, "NOP");
		      	strcat(optstr, "|");
		      }
                      break;
                    }
                    case TCPOPT_WSCALE:
                    {
                      packet_fp.wscale = (u_short)*((u_char *)(opt_ptr+i+2));
                      i+=2;
		      if ( verbose == 1)
		      {
		      	testi = sprintf(teststr, "%d", packet_fp.wscale);
		      	strcat(optstr, "WS-");
		      	strcat(optstr, teststr);
		      	strcat(optstr, "|");
		      }
                      wscale_exists = 1;
                      break;
                    }
                }
                i++;
                }
                if ( wscale_exists==0 )
                {
                  packet_fp.wscale = -1;
                }
		if ( verbose == 1)
		{
			testi = sprintf(teststr, "%d", packet_fp.psize);
			strcat(optstr, "PS-");
			strcat(optstr, teststr);
			strcat(optstr, "|");
		}
                while ( count < totfp  && found==0 )
                {
//		  packettype_cmp = strcmp(loadedfp[count].packet_type, packet_fp.packet_type);
                  if (loadedfp[count].win == packet_fp.win &&
                      loadedfp[count].mss == packet_fp.mss &&
                      loadedfp[count].df == packet_fp.df &&
                      loadedfp[count].wscale == packet_fp.wscale &&
                      loadedfp[count].sackok == packet_fp.sackok &&
                      loadedfp[count].nop == packet_fp.nop &&
                      loadedfp[count].psize == packet_fp.psize &&
		      (strcmp(loadedfp[count].packet_type, packet_fp.packet_type)) == 0)
                  {
                      for ( ttlcount=0;ttlcount<64;ttlcount++ )
                      {
                          if (loadedfp[count].ttl == ((packet_fp.ttl)+ttlcount))
                          {
                              strcpy (found_os, loadedfp[count].os);
                              found = 1;
                              count = totfp;
                          }
                          if ( found==1 )
                          {
                              break
                              ;
                          }
                      }
                  }
                  count++;
                }
		if ( verbose == 1 )
		{
			testi = sprintf(teststr, "%d", packet_fp.ttl);
			strcat(optstr, "TTL-");
			strcat(optstr, teststr);
		}
                count=0;
                if ( tcp_h->ack == 1 )
                {
                  synack=1;
                }
}

void cleanup(int signo)
{
    loop = 0;
    printf("Interrupt signal caught...\n");
}

void ht_init_table(struct table_entry **hash_table)
{
    int c;

    for (c = 0; c < HASH_TABLE_SIZE; c++)
    {
        hash_table[c] = NULL;
    }
}

int catch_sig(int signo, void (*handler)())
{
    struct sigaction action;

    action.sa_handler = handler;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;

    if (sigaction(signo, &action, NULL) == -1)
    {
        return (-1);
    }
    else
    {
        return (1);
    }
}

int load_fingerprints()
{
    char *fp;
    char *line;
    char infile[200];
    FILE *fp_file;
	int len=0;

    fp_file=fopen("disco.fp", "r");

    if (!fp_file)
    {
        fprintf(stderr, "No fingerprint file found\n");
        exit(1);
    }

    while (fgets(infile, 1500, fp_file) != NULL && infile[0] != '\n')
    {
        line = strtok ( infile, "\n");

        fp = strtok ( line, ":");
        loadedfp[totfp].win = atoi(fp);
        fp = strtok ( NULL, ":");
        loadedfp[totfp].ttl = atoi(fp);
        fp = strtok ( NULL, ":");
        loadedfp[totfp].mss = atoi(fp);
        fp = strtok ( NULL, ":");
        loadedfp[totfp].df = atoi(fp);
        fp = strtok ( NULL, ":");
        loadedfp[totfp].wscale = atoi(fp);
        fp = strtok ( NULL, ":");
        loadedfp[totfp].sackok = atoi(fp);
        fp = strtok ( NULL, ":");
        loadedfp[totfp].nop = atoi(fp);
        fp = strtok ( NULL, ":");
        loadedfp[totfp].psize = atoi(fp);
        fp = strtok ( NULL, ":");
//	loadedfp[totfp].packet_type = (char) malloc(strlen (fp)+1);
	strcpy (loadedfp[totfp].packet_type, fp);
	fp = strtok ( NULL, ":");
        loadedfp[totfp].os =  (char *) malloc(strlen (fp)+1);
        strcpy (loadedfp[totfp].os, fp);
        totfp++;
    }
    fclose(fp_file);
    return(totfp);
}

void usage(char *errmsg)
{
    fprintf(stderr,"Disco 1.2: %s\n", errmsg);
    fprintf(stderr,"\nUsage: disco  [options below]\n");
    fprintf(stderr," -i device	capture packets from device\n");
    fprintf(stderr," -N 		Do not print IP info to STDOUT\n");
    fprintf(stderr," -f 		fingerprint SYN / SYNACK packets\n");
    fprintf(stderr," -D 		discover all IPs\n");
    fprintf(stderr," -S 	        only watch for SYN packets\n");
    fprintf(stderr," -A 		watch for SYNACK packets\n");
    fprintf(stderr," -s filename	use tcpdump file for parsing\n");
    fprintf(stderr," -o filename	write output to file\n");
    fprintf(stderr," -r filter	tcpdump filter rules\n");
    fprintf(stderr," -u 	        unique ip only applies to fingerprint option\n");
    fprintf(stderr," -h 	        help - display options\n");
    fprintf(stderr," -g 		output to gherkin database - not implemented yet\n");
    fprintf(stderr," -p pipeargs	pipe output to program (see README.pipe)\n");
    fprintf(stderr," -P string	string to print before output when using -p (see README.pipe)\n");
    fprintf(stderr," -t 		timestamp IP and/or fingerprint in output file (-o)\n");
    fprintf(stderr," -v 		verbose mode - more detail when used with output file\n");
    fprintf(stderr," -e 		Ethernet Mode (certain devices with no IP assigned)\n");

    exit(1);
}

/** parse()
 *
 * See disco.h
 */

int parse(char *buf, char **args)
{
    while (*buf != NULL)
    {
        // Convert whitespace to nulls, so that the previous argument is
        // terminated automatically
        while ((*buf == ' ') || (*buf == '\t'))
            *buf++ = '\0';

        // Save the argument
        *args++ = buf;

        // Skip over the argument
        while ((*buf != NULL) && (*buf != ' ') && (*buf != '\t'))
            buf++;

    } // while (processing string)

    *args = NULL;
    return 1;

} // parse()


/** pipe_out()
 *
 * See disco.h
 */

int pipe_out(char *pre, char *str, char **args)
{
    int pid;        // PID of the child
    int status;     // Status of the child, for wait()
    int pipe_fd[2]; // File descriptor of pipe


    // Create the pipe or return failure
    if (pipe(pipe_fd) == -1)
    {
        perror("pipe_out");
        return 0;

    } // if (pipe() failed)

    // Fork off the child or return failure
    if ((pid = fork()) == -1)
    {
        perror("pipe_out");
        return 0;

    } // if (fork() failed)

    // Child
    if (pid == 0)
    {
        // Close stdin
        close( 0 );

        // Bind the read end of the pipe to stdin
        dup(pipe_fd[0]);

        // Close the read from and write to ends of the pipe
        close(pipe_fd[0]);
        close(pipe_fd[1]);

        // Fire up the reporter program
        execvp(*args, args);

        // execvp() should not return, so if it did, we have an error
        perror( "pipe_out" );
        return 0;

    } // if (child)

    // Parent
    else
    {
        int i;   // Counter

        // Close the read end of the pipe
        close(pipe_fd[0]);

        // If there is a pretext, write it
        if (pre != NULL)
        {
            for (i = 0; i < MAX_STR_LEN; i++)
                if (pre[i] == '\0')
                    break;

            write(pipe_fd[1], pre, i);

        } // if (writing pretext)

        // Give the output to the child
        for (i = 0; i < MAX_STR_LEN; i++)
            if (str[i] == '\0')
                break;

        write(pipe_fd[1], str, i);
        write(pipe_fd[1], "\n", 1);

        // Tear down the pipe (sends SIGPIPE to prog, which should make it
        // realise that it has encountered EOF)
        close(pipe_fd[1]);

        // Wait for the child to terminate
        while(wait( &status ) != pid);

    } // else (parent)

    // Success!
    return 1;

} // pipe_out()
