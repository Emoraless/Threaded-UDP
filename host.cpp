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

//Save the information about main port and neighbors
std::string main_port;
std::string main_ip;
std::string neighbor_port;
std::string neighbor_ip;
std::string neighbors;
std::string neighbor_port2;
std::string neighbors2;
std::string neighbor_ip2;
std::string neighbor_port3;
std::string neighbors3;
std::string neighbor_ip3;


#define MAX_PACKET_SIZE 1518

/* ethernet frame structure */
#define PACKET_TYPE 2
#define LLAT 2
#define LLAL 2
#define SOURCE 6
#define UNUSED 2
#define HPROTOCOL 2

char *dest_ip = "127.0.0.1";

/* IP packet structure */
#define VERSION_IHL 1
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

//To add two strigs together
char* concat(const char *s1, const char *s2)
{
    char *result = (char*)malloc(strlen(s1) + strlen(s2) + 1); // +1 for the null-terminator
    // in real code you would check for errors in malloc here
    strcpy(result, s1);
    strcat(result, s2);
    return result;
}

int parseHeader(unsigned char *packet, int packet_size)
{
    int offset = 0;                      // index offset in packet array
    unsigned char header_dest[PACKET_TYPE];         // destination address
    unsigned char link_layer_type[LLAT];
    unsigned char link_layer_length[LLAL];
    unsigned char unused[UNUSED];
    unsigned char header_source[SOURCE];    // source address
    unsigned char header_protocol[HPROTOCOL];
    
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
    unsigned char version_ihl[VERSION_IHL];
    unsigned char version[VERSION];
    uint16_t ver;
    unsigned char internet_header_length[IHL];
    uint16_t ihl;
    unsigned char type_of_service[TYPE_OF_SERVICE]; // type of service (byte 1)
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
    unsigned char precedence[PRECEDENCE];
    uint16_t prec;
    char * prec_desc;
    uint16_t delay;
    char * delay_desc;
    uint16_t throughput;
    char * throughput_desc;
    uint16_t reliability;
    char * rel_desc;
    
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
    
    struct ip* ipHeader = (struct ip*)(packet + 16);
    
    //Check to see if the destination matches the ip to print
    if((inet_ntoa(ipHeader->ip_dst) == main_ip)==1)
    {
        /* Print output */
        printf("ETHER:  ----- Ether Header -----\n");
        printf("     ETHER:\n");
        printf("     ETHER:  Packet size : %d bytes\n", packet_size);
        printf("     ETHER:  Packet type : ");
        for (int i = 0; i < PACKET_TYPE; i++)
        {
            printf("%02x", header_dest[i]);
        }
        printf("\n     ETHER:  Link-layer address type : ");
        for (int i = 0; i < LLAT; i++)
        {
            printf("%02x", link_layer_type[i]);
        }
        printf("\n     ETHER:  Link-layer address length : ");
        for (int i = 0; i < LLAL; i++)
        {
            printf("%02x", link_layer_length[i]);
        }
        printf("\n     ETHER:  Unused       : ");
        for (int i = 0; i < UNUSED; i++)
        {
            printf("%02x", unused[i]);
        }
        //printf("   Type: %s %s\n", dest_ig, dest_lg);
        printf("\n     ETHER:  Source       : %02x", header_source[0]);
        for (int i = 1; i < SOURCE; i++)
        {
            printf("-%02x", header_source[i]);
        }
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
        printf("     IP:  Version = %d\n", ver);
        printf("     IP:  Header length = %d bytes\n", ihl);
        printf("     IP:  Type of service = 0x%02x\n", type_of_service[0]);
        printf("                xxx. .... = 0 (precedence)\n");
        printf("                ...0 .... = normal delay\n");
        printf("                .... 0... = normal throughput\n");
        printf("                .... .0.. = normal reliability\n");
        printf("     IP:  Total length = %d octets\n", tot_len);
        printf("     IP:  Identification = %d\n", id);
        printf("     IP:  Flags = 0x%02x%02x\n", flags[0], flags[1]);
        printf("                .1.. .... = do not fragment\n");
        printf("                ..0. .... = last fragment\n");
        printf("     IP:  Fragment offset = %d bytes\n", frag_off);
        printf("     IP:  Time to live = %d seconds/hops\n", time_to_live[0]);
        std::cout << "     IP:  Protocol = " + std::to_string(ipHeader->ip_p) + "\n";
        printf("     IP:  Header checksum = %x%x\n", header_checksum[0], header_checksum[1]);
        printf("     IP:  Source address = %d.%d.%d.%d\n", source[0], source[1], source[2], source[3]);
        printf("     IP:  Destination address = %d.%d.%d.%d\n", dest[0], dest[1], dest[2], dest[3]);
        printf("     IP:  No options\n");
        printf("     IP:\n");
        printf("\n");
    }
    free(protocol_type);
    return 0;
}

//UDP Socket that receives the packet
void udpRecieve()
{
    int sockid;
    unsigned char packet[MAX_PACKET_SIZE];
    struct sockaddr_in servaddr, cliaddr;
    socklen_t cliaddr_len;
    int bytes_read;
    
    // Create server socket
    if ((sockid = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
    {
        perror("Failed to create socket");
        exit(0);
    }
    
    // Assign address to server
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(stoi(main_port));
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
        
        // Parse packet
        if (parseHeader(packet, bytes_read) != 0)
        {
            printf("Failed to parse packet");
            exit(0);
        }
    }
    
    // Close socket
    close(sockid);
}

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

void udpSend() {
    
    //Convert string to int
    //https://www.geeksforgeeks.org/converting-strings-numbers-cc/
    std::stringstream geek(neighbors);
    std::cout << neighbors;
    int x = 0;
    geek >> x;
    for (int i = 0; i < x; i++) {
        FILE *fp;
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
        if(i==0)
            servaddr.sin_port = htons(stoi(neighbor_port));
        else if (i==1) {
            servaddr.sin_port = htons(stoi(neighbor_port2));
        }
        else
            servaddr.sin_port = htons(stoi(neighbor_port3));
        servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
        
        // Open pcap file
        fp = fopen("/Users/Eric_Morales/Desktop/Project2Topo.pcap", "rb");
        
        // Skip over global header
        fseek(fp, GLOBAL_HEADER_SIZE, SEEK_SET);
        
        // Read first packet
        unsigned char * packet;
        int packet_size = readPacket(&packet, fp);
        
        // Read pcap file
        while (packet_size != 0)
        {
            struct ip* ipHeader = (struct ip*)(packet + 16);
            if(inet_ntoa(ipHeader->ip_src) == main_ip) {
                // Send packet to server
                sendto(sockid, packet, packet_size, 0, (struct sockaddr *)&servaddr, sizeof(servaddr));
            }
            // Read packet
            packet_size = readPacket(&packet, fp);
        }
        free(packet);
        close(sockid);
    }
}

int main(int argc, char *argv[])
{
    
    //Count the amount of lines
    int count = 0;
    
    //open the file
    std::ifstream infile("/Users/Eric_Morales/Desktop/untitled folder/1-4/1/1/1.0.txt"); //open the file
    
    //Save the information from the file
    if (infile.is_open() && infile.good()) {
        std::string line = "";
        //Read each line
        while (getline(infile, line)){
            //Save the main port ip
            if(count == 0)
                main_ip = line;
            //Save the main port number
            else if(count == 2)
                main_port = line;
            //Save number of neighbors
            else if(count == 4)
                neighbors = line;
            //Parse neighbor information
            else if(count == 6) {
                //Parse each word of the line
                //https://stackoverflow.com/questions/2323929/istringstream-how-to-do-this
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
                        neighbor_ip = tokens[i];
                    }
                    //Save neighbor port number
                    else if(counter == 2) {
                        neighbor_port = tokens[i];
                    }
                    counter++;
                }
            }
            //Parse neighbor information
            else if(count == 8) {
                //Parse each word of the line
                //https://stackoverflow.com/questions/2323929/istringstream-how-to-do-this
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
                        neighbor_ip2 = tokens[i];
                    }
                    //Save neighbor port number
                    else if(counter == 2) {
                        neighbor_port2 = tokens[i];
                    }
                    counter++;
                }
            }
            else if(count == 10) {
                //Parse each word of the line
                //https://stackoverflow.com/questions/2323929/istringstream-how-to-do-this
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
                        neighbor_ip3 = tokens[i];
                    }
                    //Save neighbor port number
                    else if(counter == 2) {
                        neighbor_port3 = tokens[i];
                    }
                    counter++;
                }
            }
            
            count++;
        }
        
    } else {
        std::cout << "Failed to open file..";
    }
    std::string response;
    std::thread first(udpRecieve);
    std::cout << "Press Enter to continue\n";
    std::cin >> response;
    std::thread second(udpSend);
    first.join();
    second.join();
    
    return 0;
}

