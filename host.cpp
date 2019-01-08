#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <string>
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>
#include <thread>



/* pcap global header structure */
#define GLOBAL_HEADER_SIZE 24
/* pcap packet header structure */
#define TIMESTAMP 4
#define MICROSECONDS 4
#define PACKET_SIZE 4
#define PACKET_LENGTH 4
#define MAX_PACKET_SIZE 1518
/* ethernet frame structure */
#define PACKET_TYPE 2
#define LLAT 2
#define LLAL 2
#define SOURCE 6
#define UNUSED 2
#define HPROTOCOL 2
/* IP packet structure */
#define VERSION_IHL 1
#define DIFF_SER_FIELD 1
#define VERSION 4 // bits
#define IHL 4 // bits
#define TYPE_OF_SERVICE 1
#define PRECEDENCE 3 // bits
#define TOTAL_LENGTH 2
#define IDENTIFICATION 2
#define FLAGS 2
#define FRAGMENT_OFFSET 13 // bits
#define TIME_TO_LIVE 1
#define PROTOCOL 1
#define HEADER_CHECKSUM 2
#define IP_SOURCE 4
#define IP_DESTINATION 4

//Save the information about main port and neighbors
unsigned char revisit = (unsigned char)1;
int revisit_num = 1;
std::string dest[11];
std::string next_hop[11];
std::string port[11];
std::string all_port[11];
std::string ip[11];
std::string main_ip = "10.0.0.1";
char *main_port = "9090";
std::string neighbors;

/*
 * This function prints the pcap header bytes that is translated
 * and displayed for the user.
 *
 */
void printBytes(unsigned char *packet, int packet_size)
{
    int row_len = 16;
    int row_count = 0;
    
    for (int i = 0; i < packet_size; i += 16)
    {
        // Print row number
        printf("00%d0 ", row_count);
        
        // Print row
        for (int j = i; j < (i + row_len); j++)
        {
            printf("%02x ", packet[j]);
        }
        
        printf("\n");
        row_count++;
    }
    printf("\n");
}

void setNextHopPort() {

    for(int i = 0; i < 11; i++) {
        for(int x = 0; x < 11; x++) {
            if(next_hop[i] == ip[x]) {
                port[i] = all_port[x];
            }
        }
    }
}

/*
 * This function
 *
 *
 *
 */
int parseField(unsigned char *field, int field_size, unsigned char *packet, int offset)
{
    // Read packet field
    for (int i = 0; i < field_size; i++)
    {
        field[i] = packet[i + offset];
    }
    
    // Return updated offset
    return offset + field_size;
}

/*
 * This function
 *
 *
 *
 */
char* concat(const char *s1, const char *s2)
{
    char *result = (char*)malloc(strlen(s1) + strlen(s2) + 1); // +1 for the null-terminator
    // in real code you would check for errors in malloc here
    strcpy(result, s1);
    strcat(result, s2);
    return result;
}

/*
 * This function
 *
 *
 *
 */
void neighborSend(unsigned char *packet, int packet_size)
{
    //Convert string to int
    std::stringstream geek(neighbors);
    int x = 0;
    //Conversion
    geek >> x;
    //Loop through all of the neighbors
    for (int i = 0; i < x-1; i++) {
        int sockid;                     // client socket
        struct sockaddr_in servaddr;    // socket address for server
        
        // Create client socket
        if ((sockid = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
        {
            printf("Failed to create socket");
            exit(0);
        }
        
        /* No need to bind because client is only sending */
        
        // Assign address to server
        servaddr.sin_family = AF_INET;
        // Determines which neighbor to send to
        servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
        //TODO
        servaddr.sin_port = htons(stoi(port[i]));
        
        // Compares host ip to packet source IP
        sendto(sockid, packet, packet_size, 0, (struct sockaddr *)&servaddr, sizeof(servaddr));
        
        close(sockid);
    }
}

/*
 * This function
 *
 *
 *
 */
int parseHeader(unsigned char *packet, int packet_size)
{
    struct ip* ipHeader = (struct ip*)(packet + 16);
    
    //Check to see if the destination matches the ip to print
    if((inet_ntoa(ipHeader->ip_dst) == main_ip)==1)
    {
        /* Linus Cooked Capture Header */
        int offset = 0;                      // index offset in packet array
        unsigned char header_dest[PACKET_TYPE];         // destination address
        unsigned char link_layer_type[LLAT];
        unsigned char link_layer_length[LLAL];
        unsigned char unused[UNUSED];
        unsigned char header_source[SOURCE];    // source address
        unsigned char header_protocol[HPROTOCOL];\
        /* IP Header */
        unsigned char version_ihl[VERSION_IHL];
        unsigned char version[VERSION];
        uint16_t ver;
        unsigned char internet_header_length[IHL];
        uint16_t ihl;
        unsigned char type_of_service[TYPE_OF_SERVICE]; // type of service (byte 1)
        unsigned char precedence[PRECEDENCE];
        uint16_t prec;
        char * prec_desc;
        uint16_t delay;
        char * delay_desc;
        uint16_t throughput;
        char * throughput_desc;
        uint16_t reliability;
        char * rel_desc;
        unsigned char total_length[TOTAL_LENGTH];       // total length (bytes 2-3)
        uint16_t tot_len;
        unsigned char identification[IDENTIFICATION];   // identification (bytes 4-5)
        uint16_t id;
        unsigned char flags[FLAGS];                     // fragment offset (bytes 6-7)
        unsigned char fragment_offset[FRAGMENT_OFFSET];
        uint16_t frag_off;
        unsigned char time_to_live[TIME_TO_LIVE];       // time to live (byte 8)
        unsigned char protocol[PROTOCOL];               // protocol (byte 9)
        char * protocol_type;
        unsigned char header_checksum[HEADER_CHECKSUM]; // header checksum (bytes 10-11)
        unsigned char source[IP_SOURCE];                // source (bytes 12-15)
        unsigned char dest[IP_DESTINATION];             // destination (bytes 16-19)
        
        /* Parse fields packet header  */
        //Packet type
        offset = parseField(header_dest, PACKET_TYPE, packet, offset);
        //Link layer type
        offset = parseField(link_layer_type , LLAT, packet, offset);
        //Link layer length
        offset = parseField(link_layer_length , LLAL, packet, offset);
        //Header source
        offset = parseField(header_source, SOURCE, packet, offset);
        //Unused
        offset = parseField(unused , UNUSED, packet, offset);
        //Protocol
        offset = parseField(header_protocol , HPROTOCOL, packet, offset);
        
        //After the header bits
        offset = 16;
        /* Parse fields */
        // Version and Internet header length (IHL)
        offset = parseField(version_ihl, VERSION_IHL, packet, offset);
        // Version
        // Parse version bits into array from version_ihl byte
        for (int i = 0; i < VERSION; i++)
        {
            version[i] = (version_ihl[0] >> (7 - i)) & 1;
        }
        // Convert array of version bits to integer
        ver = (version[0] << 3)
        | (version[1] << 2)
        | (version[2] << 1)
        | (version[3]);
        // Internet header length (IHL)
        // Parse IHL bits into array from version_ihl byte
        for (int i = 0; i < IHL; i++)
        {
            internet_header_length[i] = (version_ihl[0] >> (3 - i)) & 1;
        }
        // Convert array of IHL bits to integer
        ihl = (internet_header_length[0] << 3)
        | (internet_header_length[1] << 2)
        | (internet_header_length[2] << 1)
        | (internet_header_length[3]);
        ihl *= 4;
        // Type of service
        offset = parseField(type_of_service, TYPE_OF_SERVICE, packet, offset);
        // Parse precedence bits into array from type_of_service
        for (int i = 0; i < PRECEDENCE; i++)
        {
            precedence[i] = (type_of_service[0] >> (7 - i)) & 1;
        }
        // Convert array of precedence bits to integer
        prec = (precedence[0] << 2)
        | (precedence[1] << 1)
        | (precedence[2]);
        // Determine description of precedence
        switch (prec)
        {
            case 1:
                prec_desc = "priority";
                break;
            case 2:
                prec_desc = "immediate";
                break;
            case 3:
                prec_desc = "flash";
                break;
            case 4:
                prec_desc = "flash override";
                break;
            case 5:
                prec_desc = "critical";
                break;
            case 6:
                prec_desc = "internetwork control";
                break;
            case 7:
                prec_desc = "network control";
                break;
            default:
                prec_desc = "routine";
        }
        // Check delay bit
        delay = (type_of_service[0] >> 4) & 1;
        if (delay == 1)
            delay_desc = "low";
        else
            delay_desc = "normal";
        // Check throughput bit
        throughput = (type_of_service[0] >> 3) & 1;
        if (throughput == 1)
            throughput_desc = "high";
        else
            throughput_desc = "normal";
        // Check reliability bit
        reliability = (type_of_service[0] >> 2) & 1;
        if (reliability == 1)
            rel_desc = "high";
        else
            rel_desc = "normal";
        // Total length
        offset = parseField(total_length, TOTAL_LENGTH, packet, offset);
        tot_len = (total_length[0] << 8) | (total_length[1]);
        // Identification
        offset = parseField(identification, IDENTIFICATION, packet, offset);
        id = (identification[1] << 8) | (identification[0]);
        // Flags
        offset = parseField(flags, FLAGS, packet, offset);
        // Parse fragment offset bits into array
        for (int i = 0; i < 5; i++)
        {
            fragment_offset[i] = (flags[0] >> (5 - i)) & 1;
        }
        for (int i = 5; i < FRAGMENT_OFFSET; i++)
        {
            fragment_offset[i] = (flags[1] >> (8 - i)) & 1;
        }
        // Convert fragment offset bits into integer
        frag_off =  (fragment_offset[0] >> 12)
        | (fragment_offset[1] >> 11)
        | (fragment_offset[2] >> 10)
        | (fragment_offset[3] >> 9)
        | (fragment_offset[4] >> 8)
        | (fragment_offset[5] >> 7)
        | (fragment_offset[6] >> 6)
        | (fragment_offset[7] >> 5)
        | (fragment_offset[8] >> 4)
        | (fragment_offset[9] >> 3)
        | (fragment_offset[10] >> 2)
        | (fragment_offset[11] >> 1)
        | fragment_offset[12];
        // Time to live
        offset = parseField(time_to_live, TIME_TO_LIVE, packet, offset);
        // Protocol
        offset = parseField(protocol, PROTOCOL, packet, offset);
        // Determine protocol type
        if (protocol[0] == 0x06)
        {
            protocol_type = (char*)malloc(strlen("TCP"));
            strcpy(protocol_type, "TCP");
        }
        else if (protocol[0] == 0x11)
        {
            protocol_type = (char*)malloc(strlen("UDP"));
            strcpy(protocol_type, "UDP");
        }
        else
        {
            protocol_type = (char*)malloc(strlen("UNKNOWN"));
            strcpy(protocol_type, "UNKNOWN");
        }
        // Header checksum
        offset = parseField(header_checksum, HEADER_CHECKSUM, packet, offset);
        // Source address
        offset = parseField(source, IP_SOURCE, packet, offset);
        // Destination address
        offset = parseField(dest, IP_DESTINATION, packet, offset);
        
        /* Print output */
        printf("ETHER:  ----- Ether Header -----\n");
        printf("     ETHER:\n");
        // Print packet size
        printf("     ETHER:  Packet size : %d bytes\n", packet_size);
        // Print packet type
        printf("     ETHER:  Packet type : ");
        for (int i = 0; i < PACKET_TYPE; i++)
        {
            printf("%02x", header_dest[i]);
        }
        // Print packet link-layer type
        printf("\n     ETHER:  Link-layer address type : ");
        for (int i = 0; i < LLAT; i++)
        {
            printf("%02x", link_layer_type[i]);
        }
        // Print packet link-layer address length
        printf("\n     ETHER:  Link-layer address length : ");
        for (int i = 0; i < LLAL; i++)
        {
            printf("%02x", link_layer_length[i]);
        }
        // Print packet unused
        printf("\n     ETHER:  Unused       : ");
        for (int i = 0; i < UNUSED; i++)
        {
            printf("%02x", unused[i]);
        }
        // Print packet source
        printf("\n     ETHER:  Source       : %02x", header_source[0]);
        for (int i = 1; i < SOURCE; i++)
        {
            printf("-%02x", header_source[i]);
        }
        // Printer packet protocol
        printf("\n     ETHER:  Protocol       : ");
        for (int i = 0; i < HPROTOCOL; i++)
        {
            printf("%02x", header_protocol[i]);
        }
        printf("\n     ETHER:\n");
        printf("\n");
        
        /* Print output */
        printf("     IP:  ----- IP Header -----\n");
        printf("     IP:\n");
        // Print IP packet version
        printf("     IP:  Version = %d\n", ver);
        // Print IP header length
        printf("     IP:  Header length = %d bytes\n", ihl);
        // Print IP header TOS
        printf("     IP:  Type of service = 0x%02x\n", type_of_service[0]);
        printf("                xxx. .... = %d (%s)\n", prec, prec_desc);
        printf("                ...%d .... = %s delay\n", delay, delay_desc);
        printf("                .... %d... = %s throughput\n", throughput, throughput_desc);
        printf("                .... .%d.. = %s reliability\n", reliability, rel_desc);
        // Print IP header total length
        printf("     IP:  Total length = %d octets\n", tot_len);
        // Print IP header id
        printf("     IP:  Identification = %d\n", ipHeader->ip_id);
        // Print IP header flags
        printf("     IP:  Flags = 0x%02x%02x\n", flags[0], flags[1]);
        printf("                .%d.. .... = do not fragment\n", ((flags[0] >> 6) & 1));
        printf("                ..%d. .... = last fragment\n", ((flags[0] >> 5) & 1));
        // Print IP header fragment offset
        printf("     IP:  Fragment offset = %d bytes\n", frag_off);
        // Print IP header TTL
        printf("     IP:  Time to live = %d seconds/hops\n", time_to_live[0]);
        // Print IP header protocol
        printf("     IP:  Protocol = %d (%s)\n", protocol[0], protocol_type);
        // Print IP header checksum
        printf("     IP:  Header checksum = %x%x\n", header_checksum[0], header_checksum[1]);
        // Print IP header source address
        printf("     IP:  Source address = %d.%d.%d.%d\n", source[0], source[1], source[2], source[3]);
        // Print IP header destination address
        printf("     IP:  Destination address = %d.%d.%d.%d\n", dest[0], dest[1], dest[2], dest[3]);
        printf("     IP:  No options\n");
        printf("     IP:\n");
        printf("\n");
        
        //free(protocol_type);
    }
    // If the destination do not match, send to neighbor. Except the
    else {
        neighborSend(packet, packet_size);
    }
    return 0;
}

/*
 * This function
 *
 *
 *
 */
struct packet_hdr
{
    unsigned char timestamp[TIMESTAMP];         // POSIX timestamp of packet capture
    unsigned char microseconds[MICROSECONDS];   // number of microseconds at packet capture time
    unsigned char packet_size[PACKET_SIZE];     // size in bytes of packet data
    unsigned char packet_length[PACKET_LENGTH]; // length in bytes of packet data
};

/*
 * This function reads a pcap packet header from the file stream pointed to by fp
 * and stores the packet header information in pkt_hdr.
 *
 * The function returns 0 if successful, else -1.
 */
int readPacketHeader(struct packet_hdr *pkt_hdr, FILE *fp)
{
    if (fread(pkt_hdr->timestamp, sizeof(unsigned char), TIMESTAMP, fp) != TIMESTAMP)
        return -1;
    
    if (fread(pkt_hdr->microseconds, sizeof(unsigned char), MICROSECONDS, fp) != MICROSECONDS)
        return -1;
    
    if (fread(pkt_hdr->packet_size, sizeof(unsigned char), PACKET_SIZE, fp) != PACKET_SIZE)
        return -1;
    
    if (fread(pkt_hdr->packet_length, sizeof(unsigned char), PACKET_LENGTH, fp) != PACKET_LENGTH)
        return -1;
    
    return 0;
}

/*
 * This function
 *
 *
 *
 */
int readPacket(unsigned char **packet, FILE *fp)
{
    // Read packet header
    struct packet_hdr pkt_hdr;
    readPacketHeader(&pkt_hdr, fp);
    
    // Get packet size from packet header
    // Convert packet_size byte array to int
    uint16_t packet_size = (pkt_hdr.packet_size[3] << 24)
    | (pkt_hdr.packet_size[2] << 16)
    | (pkt_hdr.packet_size[1] << 8)
    | pkt_hdr.packet_size[0];
    
    // Allocate memory for packet data
    *packet = (unsigned char*) malloc(packet_size);
    
    // Read packet data
    return fread(*packet, sizeof(unsigned char), packet_size, fp);
}

/*
 * This function
 *
 *
 *
 */
void udpRecieve()
{
    int sockid;
    unsigned char packet[MAX_PACKET_SIZE];
    struct sockaddr_in servaddr, cliaddr;
    socklen_t cliaddr_len;
    int bytes_read = 0;
    int currentBytes = 1;
    
    // Create server socket
    if ((sockid = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
    {
        perror("Failed to create socket");
        exit(0);
    }
    
    // Assign address to server
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(std::stoi(main_port));
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    
    // Bind server socket to address
    if (bind(sockid, (struct sockaddr *) &servaddr, sizeof(servaddr)) < 0)
    {
        perror("Failed to bind socket");
        exit(0);
    }
    
    // Listen indefintely for messages from client
    while (1)
    {
        // Clear packet buffer
        memset(packet, 0, MAX_PACKET_SIZE);
        
        // Receive packet from client
        bytes_read = recvfrom(sockid, packet, MAX_PACKET_SIZE, 0, (struct sockaddr *)&cliaddr, &cliaddr_len);
        
        if(currentBytes != bytes_read) {
            // Parse packet
            if (parseHeader(packet, bytes_read) != 0)
            {
                printf("Failed to parse packet");
                exit(0);
            }
        }
        currentBytes = bytes_read;
    }
    
    // Close socket
    close(sockid);
}

/*
 * This function
 *
 *
 *
 */
void udpSend() {
    
    //Convert string to int
    std::stringstream geek(neighbors);
    int x = 0;
    //Conversion
    geek >> x;
    //Loop through all of the neighbors
    for (int i = 0; i < x-1; i++) {

        FILE *fp;                       // File name
        int sockid;                     // client socket
        struct sockaddr_in servaddr;    // socket address for server
        
        // Create client socket
        if ((sockid = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
        {
            printf("Failed to create socket");
            exit(0);
        }
        
        /* No need to bind because client is only sending */
        
        // Assign address to server
        servaddr.sin_family = AF_INET;
        
        // Determines which neighbor to send to
        servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
        //TODO
        servaddr.sin_port = htons(stoi(port[i]));;
        
        // Open pcap file
        fp = fopen("/Users/Eric_Morales/Desktop/Project4input.pcap", "rb");
        
        // Skip over global header
        fseek(fp, GLOBAL_HEADER_SIZE, SEEK_SET);
        
        // Read first packet
        unsigned char * packet;
        int packet_size = readPacket(&packet, fp);
        
        // Read pcap file
        while (packet_size != 0)
        {
            // IP header
            struct ip* ipHeader = (struct ip*)(packet + 16);
            // Compares host ip to packet source IP
            if(inet_ntoa(ipHeader->ip_src) == main_ip) {
                if (inet_ntoa(ipHeader->ip_dst) == dest[i]) {
                // Send packet to server
                sendto(sockid, packet, packet_size, 0, (struct sockaddr *)&servaddr, sizeof(servaddr));
                }
            }
            // Read packet
            packet_size = readPacket(&packet, fp);
        }
        free(packet);
        close(sockid);
    }
}
void readIpPort(){
    // Count the amount of lines
    int count = 0;
    // Track neighbors
    int track = 0;
    //open the file
    std::ifstream infile("IP/port file location"); //open the file
    //Save the information from the file
    if (infile.is_open() && infile.good()) {
        std::string line = "";
        //Read each line
        while (getline(infile, line)){
            //Parse each word of the line
            std::string s;
            std::istringstream iss(line);
            std::istream_iterator<std::string> beg(iss), end;
            std::vector<std::string> tokens(beg, end);
            //count each word
            int counter = 0;
            //Parse each information
            for(int i = 0; i<tokens.size();i++){
                //Save neighbor ip
                if(counter == 0) {
                    ip[count] = tokens[i];
                }
                //Save neighbor port number
                else if(counter == 1) {
                    all_port[count] = tokens[i];
                    track++;
                }
                counter++;
            }
            count++;
        }
        
    } else {
        std::cout << "Failed to open file..";
    }
    
    return;
}

/*
 * This function
 *
 */
void readNeighbors(){
    // Count the amount of lines
    int count = 0;
    // Track neighbors
    int track = 0;
    
    //open the file
    std::ifstream infile("neighbor file location"); //open the file
    //Save the information from the file
    if (infile.is_open() && infile.good()) {
        std::string line = "";
        //Read each line
        while (getline(infile, line)){
            //Save the main port ip
            if(count == 0) {
                neighbors = line;
            }
            //Parse neighbor information
            else if(count > 1) {
                //Parse each word of the line
                std::string s;
                std::istringstream iss(line);
                std::istream_iterator<std::string> beg(iss), end;
                std::vector<std::string> tokens(beg, end);
                //count each word
                int counter = 0;
                //Parse each information
                for(int i = 0; i<tokens.size();i++){
                    //Save neighbor ip
                    if(counter == 0) {
                        dest[track] = tokens[i];
                    }
                    //Save neighbor port number
                    else if(counter == 1) {
                        next_hop[track] = tokens[i];
                        track++;
                    }
                    counter++;
                }
            }
            count++;
        }
        
    } else {
        std::cout << "Failed to open file..";
    }
    
    return;
}

/*
 * This function runs the main part of the program. 
 *
 */
int main(int argc, char *argv[])
{
    // Reads neighbors and sets up main/neighbors ports and IP's
    readNeighbors();
    // Read the all IP's and port number associated to IP
    readIpPort();
    // Set the next destination
    setNextHopPort();
    // Thread that sets up method ready to be receive any packets from neighbors
    std::thread first(udpRecieve);
    // Wait command, to set up UDP receive before other's send information
    std::string response;
    std::cout << "Press Enter to continue\n";
    std::cin >> response;
    // Thread that checks pcap topology to be able to send packets to neighbors
    std::thread second(udpSend);
    // Thread join together
    first.join();
    second.join();
    
    return 0;
}

