/*
 * Copyright (c) 2009 Vineyard Networks Inc. (http://www.vineyardnetworks.com)
 * All rights reserved.
 *
 * This file is part of the Network Application Visibility Libary.
 *
 * Helper file for protocol name lookup
 *
 */

#ifndef GUIDS_H
#define GUIDS_H

#ifdef __cplusplus
extern "C" {
#endif

/* FRAME TYPES */
#define GUID_ETH      	"ETH"		/* Ethernet */

/* ETH */
#define GUID_IP			"IP"		/* Internet Protocol */
#define GUID_IPV6     	"IPV6"		/* Internet Protocol Version 6*/
#define GUID_X25		"X.25"		/* X.25 */
#define GUID_ARP		"ARP"		/* Address Resolution Protocol */
#define GUID_RARP		"RARP"		/* Reverse Address Resolution Protocol */
#define GUID_APPLARP	"APPLARP"	/* Apple ARP */
#define GUID_IPX		"IPX"		/* Internetwork Packet Exchange */
#define GUID_SLOW		"SLOW"		/* */
#define GUID_WCCP		"WCCP"		/* Web Cache Communication Protocol */
#define GUID_PPPDISC	"PPPDISC"	/* PPPDiscovery */
#define GUID_PPPSESS	"PPPSESS"	/* PPPSession */
#define GUID_MPLSUC		"MPLSUC"	/* Multiprotocol Label Switching Unicast */
#define GUID_MPLSMC		"MPLSMC"	/* Multiprotocol Label Switching Multicast*/
#define GUID_ATMMPOA	"ATMMPOA"	/* Multi-protocol over ATM */
#define GUID_ATMFATE	"ATMFATE"	/* Frame-based ATM Transport over Ethernet */


/* IP Protos */
#define GUID_ICMP		"ICMP"		/* Internet Control Message Protocol */
#define GUID_IGMP		"IGMP"		/* Internet Group Management Protocol */
#define GUID_IPIP		"IPIP"		/* Internet Protocol Within Internet Protocol */
#define GUID_EGP		"EGP"		/* Exterior Gateway Protocol */
#define GUID_PUP		"PUP"		/* PARC Universal Packet */
#define GUID_IDP		"IDP"		/* Internet Datagram Protocol */
#define GUID_DCCP		"DCCP"		/* Datagram Congestion Control Protocol */
#define GUID_RSVP		"RSVP"		/* Resource Reservation Protocol */
#define GUID_GRE		"GRE"		/* Generic Route Encapsulation Protocol */
#define GUID_ESP		"ESP"		/* Encapsulating Security Payload */
#define GUID_AH			"AH"		/* Authentication Header */
#define GUID_BEETPH		"BEETPH"	/* */
#define GUID_PIM		"PIM"		/* Protocol Independent Multicast */
#define GUID_IPCOMP		"IPCOMP"	/* IP Payload Compression Protocol */
#define GUID_SCTP		"SCTP"		/* Stream Control Transmission Protocol */
#define GUID_TCP		"TCP"		/* Transmission Control Protocol */
#define GUID_UDP		"UDP"		/* User Datagram Protocol */
#define GUID_ICMPV6		"ICMPV6"	/* Internet Control Message Protocol for IPv6 */


/* IANA well-known ports < 1024 */
#define GUID_TCPMUX		"TCPMUX"	/* TCP Port Service Multiplexer */
#define GUID_CMPRSNET	"CMPRSNET"	/* Compression Process */
#define GUID_RJE		"RJE"		/* Remote Job Entry */
#define GUID_ECHO		"ECHO"		/* Echo */
#define GUID_DISCARD	"DISCARD"	/* Discard */
#define GUID_SYSTAT		"SYSTAT"	/* Systat */
#define GUID_DAYTIME	"DAYTIME"	/* Daytime Protocol */
#define GUID_QOTD		"QOTD"		/* Quote of the Day */
#define GUID_MSP		"MSP"		/* Message Send Protocol */
#define GUID_CHARGEN	"CHARGEN"	/* Character Generator */
#define GUID_FTP		"FTP"		/* File Transfer Protocol control flow */
#define GUID_FTPCTRL	"FTPCTRL"	/* File Transfer Protocol data flow */
#define GUID_FTPDATA	"FTPDATA"	/* File Transfer Protocol data flow */
#define GUID_SSH		"SSH"		/* Secure Shell protocol */
#define GUID_TELNET		"TELNET"	/* Telnet */
#define GUID_SMTP		"SMTP"		/* Simple Mail Transfer Protocol */
#define GUID_MSG		"MSG"		/* msg-icp & msg-auth */
#define GUID_DSP		"DSP"		/* Display support protocol */
#define GUID_TIME		"TIME"		/* Time */
#define GUID_RAP		"RAP"		/* Route Access Protocol */
#define GUID_RLP		"RLP"		/* Resource Location Protocol */
#define GUID_WINS		"WINS"		/* Wins Host Name Server */
#define GUID_WHOIS		"WHOIS"		/* Who Is */
#define GUID_MPM		"MPM"		/* Message Processing Module */
#define GUID_NIFTP		"NIFTP"		/* NI FTP */
#define GUID_AUDITD		"AUDITD"	/* Digital Audit Daemon */
#define GUID_TACACS		"TACACS"	/* Terminal Access Controller Access-Control System */
#define GUID_REMAIL		"REMAIL"	/* Remote Mail Checking Protocol */
#define GUID_LAMAINT	"LAMAINT"	/* IMP Logical Address maintenance */
#define GUID_XNSTIME	"XNSTIME"	/* XNS Time Protocol */
#define GUID_DNS		"DNS"		/* Domain Name Server */
#define GUID_XNSCH		"XNSCH"		/* XNS Clearinghouse */
#define GUID_ISIGL		"ISIGL"		/* ISI Graphics Language */
#define GUID_XNSAUTH	"XNSAUTH"	/* XNS Authentication */
#define GUID_XNSMAIL	"XNSMAIL"	/* XNS Mail */
#define GUID_NIMAIL		"NIMAIL"	/* NI MAIL */
#define GUID_ACAS		"ACAS"		/* ACA Service */
#define GUID_COVIA		"COVIA"		/* Communications Integrator */
#define GUID_SQLNET		"SQLNET"	/* Oracle SQL*NET */
#define GUID_DHCP		"DHCP"		/* Dynamic Host Configuration Protocol */
#define GUID_TFTP		"TFTP"		/* Trivial File Transfer Protocol */
#define GUID_GOPHER		"GOPHER"	/* Gopher */
#define GUID_RJS		"RJS"		/* Remote Job Service */
#define GUID_DEOS		"DEOS"		/* Distributed External Object Store */
#define GUID_VETTCP		"VETTCP"	/* Vettcp */
#define GUID_FINGER		"FINGER"	/* Finger */
#define GUID_HTTP		"HTTP"		/* Hypertext Transfer Protocol */
#define GUID_XFER		"XFER"		/* XFER Utility */
#define GUID_MLDEV		"MLDEV"		/* MIT ML Device */
#define GUID_CTF		"CTF"		/* Common Trace Facility */
#define GUID_MFCOBOL	"MFCOBOL"	/* Micro Focus Cobol */
#define GUID_KERBEROS	"KERBEROS"	/* Kerberos Security */
#define GUID_SUTLNT		"SUTLNT"	/* Su-Mit Telnet Gateway */
#define GUID_DNSIX		"DNSIX"		/* DODIIS Network Security Information Exchange */
#define GUID_MITSPL		"MITSPL"	/* MIT Dover Spooler */
#define GUID_NPP		"NPP"		/* Network Printing Protocol */
#define GUID_DCP		"DCP"		/* Device Control Protocol */
#define GUID_TIVOLI		"TIVOLI"	/* Tivoli Object Dispatcher */
#define GUID_SUPDUP		"SUPDUP"	/* Supdup Protocol */
#define GUID_DIXIE		"DIXIE"		/* Dixie Protocol Specification */
#define GUID_SWIFTRVF	"SWIFTRVF"	/* Swift Remote Virtural File Protocol */
#define GUID_TACNEWS	"TACNEWS"	/* TAC News */
#define GUID_METAGRAM	"METAGRAM"	/* Metagram Relay */
#define GUID_HOSTNAME	"HOSTNAME"	/* NIC Host Name Server */
#define GUID_ISOTSAP	"ISOTSAP"	/* ISO-TSAP Class */
#define GUID_GPITNP		"GPITNP"	/* Genesis Point-to-Point Trans Net */
#define GUID_ACRNEMA	"ACRNEMA"	/* ACR-NEMA Digital Image */
#define GUID_CSNETNS	"CSNETNS"	/* csnet-ns Mailbox Name Nameserver */
#define GUID_3COMTSMX	"3COMTSMX"	/* 3COM-TSMUX Queuing Protocol */
#define GUID_RTELNET	"RTELNET"	/* Remote Telnet */
#define GUID_SNAGAS		"SNAGAS"	/* SNA Gateway Access Server */
#define GUID_POP2		"POP2"		/* Post Office Protocol 2 */
#define GUID_POP3		"POP3"		/* Post Office Protocol 3 */
#define GUID_SUNRPC		"SUNRPC"	/* SUN Remote Procedure Call */
#define GUID_MCIDAS		"MCIDAS"	/* McIDAS Data Transmission Protocol */
#define GUID_IDENT		"IDENT"		/* Identification */
#define GUID_SFTP		"SFTP"		/* Simple File Transfer Protocol */
#define GUID_ANSANTFY	"ANSANTFY"	/* ANSA REX Notify */
#define GUID_UUCP		"UUCP"		/* Unix-to-Unix Copy */
#define GUID_SQLSERV	"SQLSERV"	/* SQL Server */
#define GUID_NNTP		"NNTP"		/* Network News Transfer Protocol */
#define GUID_CFDPTKT	"CFDPTKT"	/* CFDPTKT */
#define GUID_ERPC		"ERPC"		/* Encore Expedited Remote Procedure Call */
#define GUID_SMAKYNET	"SMAKYNET"	/* SmakyNet */
#define GUID_NTP		"NTP"		/* Network Time Protocol */
#define GUID_ANSATRDR	"ANSATRDR"	/* ANSA REX Trader */
#define GUID_LOCUSMAP	"LOCUSMAP"	/* Locus PC-Interface Net Map */
#define GUID_NXEDIT		"NXEDIT"	/* NXEdit */
#define GUID_LOCUSCON	"LOCUSCON"	/* Locus PC-Interface Conn */
#define GUID_GSSLIC		"GSSLIC"	/* Gss X License Verification */
#define GUID_PWDGEN		"PWDGEN"	/* Password Generator Protocol */
#define GUID_CISCOFNA	"CISCOFNA"	/* cisco FNATIVE */
#define GUID_CISCOTNA	"CISCOTNA"	/* cisco TNATIVE */
#define GUID_CISCOSYS	"CISCOSYS"	/* cisco SYSMAINT */
#define GUID_STATSRV	"STATSRV"	/* Statistics Service */
#define GUID_INGRSNET	"INGRSNET"	/* INGRES-NET Service */
#define GUID_EPMAP		"EPMAP"		/* DCE endpoint resolution */
#define GUID_PROFILE	"PROFILE"	/* PROFILE Naming System */
#define GUID_NETBIOS	"NETBIOS"	/* NETBIOS Service */
#define GUID_EMFIS		"EMFIS"		/* EMFIS */
#define GUID_BLIDM		"BLIDM"		/* Britton-Lee IDM */
#define GUID_IMAP		"IMAP"		/* Internet Message Access Protocol */
#define GUID_UMA		"UMA"		/* Universal Management Architecture */
#define GUID_UAAC		"UAAC"		/* UAAC Protocol */
#define GUID_ISOIP		"ISOIP"		/* ISO-IP */
#define GUID_JARGON		"JARGON"	/* Jargon */
#define GUID_AED512		"AED512"	/* AED 512 Emulation Service */
#define GUID_HEMS		"HEMS"		/* HEMS */
#define GUID_BFTP		"BFTP"		/* Background File Transfer Program */
#define GUID_SGMP		"SGMP"		/* Simple Gateway Monitoring Protocol */
#define GUID_NETSC		"NETSC"		/* NetSC */
#define GUID_KNETCMP	"KNETCMP"	/* KNET/VM Command/Message Protocol */
#define GUID_PCMAIL		"PCMAIL"	/* PCMail Server */
#define GUID_NSS		"NSS"		/* NSS-Routing */
#define GUID_SNMP		"SNMP"		/* Simple Network Management Protocol */
#define GUID_CMIP		"CMIP"		/* Common Management Information Protocol */
#define GUID_XNS		"XNS"		/* Xerox */
#define GUID_SNET		"SNET"		/* Sirius Systems */
#define GUID_NAMP		"NAMP"		/* NAMP */
#define GUID_RSVD		"RSVD"		/* RSVD */
#define GUID_SEND		"SEND"		/* SEND */
#define GUID_PRINTSRV	"PRINTSRV"	/* Network PostScript */
#define GUID_MULTPLEX	"MULTPLEX"	/* Network Innovations Multiplex */
#define GUID_CL1		"CL1"		/* Network Innovations CL/1 */
#define GUID_XYPLEX		"XYPLEX"	/* Xyplex */
#define GUID_MAILQ		"MAILQ"		/* MAILQ */
#define GUID_VMNET		"VMNET"		/* VMNET */
#define GUID_GENRAD		"GENRAD"	/* GENRAD-MUX */
#define GUID_XDMCP		"XDMCP"		/* X Display Manager Control Protocol */
#define GUID_NXTSTEP	"NXTSTEP"	/* NextStep Window Server */
#define GUID_BGP		"BGP"		/* Border Gateway Protocol */
#define GUID_RIS		"RIS"		/* Intergraph */
#define GUID_UNIFY		"UNIFY"		/* Unify */
#define GUID_AUDIT		"AUDIT"		/* Unisys Audit SITP */
#define GUID_OCBINDER	"OCBINDER"	/* OCBinder */
#define GUID_OCSERVER	"OCSERVER"	/* OCServer */
#define GUID_KIS		"KIS"		/* KIS Protocol */
#define GUID_ACI		"ACI"		/* Application Communication Interface */
#define GUID_MUMPS		"MUMPS"		/* Plus Five MUMPS */
#define GUID_QFT		"QFT"		/* Queued File Transport */
#define GUID_GACP		"GACP"		/* Gateway Access Control Protocol */
#define GUID_PROSPERO	"PROSPERO"	/* Prospero Directory Service */
#define GUID_OSUNMS		"OSUNMS"	/* OSU Network Monitoring System */
#define GUID_SRMP		"SRMP"		/* Spider Remote Monitoring Protocol */
#define GUID_IRC		"IRC"		/* Internet Relay Chat Protocol */
#define GUID_DLS		"DLS"		/* Directory Location Service */
#define GUID_SMUX		"SMUX"		/* SNMP multiplexing */
#define GUID_SRC		"SRC"		/* IBM System Resource Controller */
#define GUID_APPLTALK	"APPLTALK"	/* AppleTalk */
#define GUID_QMTP		"QMTP"		/* Quick Mail Transfer Protocol */
#define GUID_Z3950		"Z3950"		/* ANSI Z39.50 */
#define GUID_914CG		"914CG"		/* Texas Instruments 914C/G Terminal */
#define GUID_ANET		"ANET"		/* ATEXSSTR */
#define GUID_VMPWSCS	"VMPWSCS"	/* VM PWSCS */
#define GUID_SOFTPC		"SOFTPC"	/* SoftPC */
#define GUID_CAILIC		"CAILIC"	/* Computer Associates Int'l License Server */
#define GUID_DBASE		"DBASE"		/* dBASE Unix */
#define GUID_MPP		"MPP"		/* Netix Message Posting Protocol */
#define GUID_UARPS		"UARPS"		/* Unisys ARPs */
#define GUID_RLOGIN		"RLOGIN"	/* Remote login */
#define GUID_RSH		"RSH"		/* Berkeley Remote Shell Service */
#define GUID_CDC		"CDC"		/* Certificate Distribution Center */
#define GUID_MASQDIAL	"MASQDIAL"	/* Masqdialer */
#define GUID_DIRECT		"DIRECT"	/* Direct */
#define GUID_SURMEAS	"SURMEAS"	/* Survey Measurement */
#define GUID_INBSNESS	"INBSNESS"	/* InBusiness */
#define GUID_LINK		"LINK"		/* LINK */
#define GUID_DSP3270	"DSP3270"	/* Display Systems Protocol */
#define GUID_SBNTBCST	"SBNTBCST"	/* SUBNTBCST Trivial File Transfer Protocol */
#define GUID_BHFHS		"BHFHS"		/* BHFHS */
#define GUID_SET		"SET"		/* Secure Electronic Transaction */
#define GUID_ESRO		"ESRO"		/* Efficient Short Remote Operations */
#define GUID_OPENPORT	"OPENPORT"	/* Openport */
#define GUID_NSIIOPS	"NSIIOPS"	/* IIOP Name Service */
#define GUID_ARCISDMS	"ARCISDMS"	/* Arcisdms */
#define GUID_HDAP		"HDAP"		/* Microsoft HDA Protocol */
#define GUID_BGMP		"BGMP"		/* Border Gateway Multicast Protocol */
#define GUID_XBONE		"XBONE"		/* X-Bone Control */
#define GUID_SCSIST		"SCSIST"	/* SCSI on ST */
#define GUID_TOBITDAV	"TOBITDAV"	/* Tobit David Service Layer */
#define GUID_MANET		"MANET"		/* Mobile Ad-hoc Networks Protocol */
#define GUID_GIST		"GIST"		/* General Internet Signalling Transport */
#define GUID_HTTPMGT	"HTTPMGT"	/* HTTP Managment */
#define GUID_PRSNLINK	"PRSNLINK"	/* Personal Link */
#define GUID_CBLPRTAX	"CBLPRTAX"	/* Cable Port A/X */
#define GUID_RESCAP		"RESCAP"	/* rescap Resolution Protocol */
#define GUID_CORERJD	"CORERJD"	/* Corerjd */
#define GUID_FXP		"FXP"		/* File eXchange Protocol */
#define GUID_KBLOCK		"KBLOCK"	/* K-BLOCK */
#define GUID_NOVABKUP	"NOVABKUP"	/* Novastor Backup */
#define GUID_NTRSTIME	"NTRSTIME"	/* EntrustTime */
#define GUID_BHMDS		"BHMDS"		/* bhmds */
#define GUID_APPLSHAR	"APPLSHAR"	/* AppleShare IP WebAdmin */
#define GUID_VSLMP		"VSLMP"		/* voipswitch Live Management System */
#define GUID_MGNTALOG	"MGNTALOG"	/* Magenta Logic */
#define GUID_OPALIS		"OPALIS"	/* Opalis Robot */
#define GUID_DPSI		"DPSI"		/* DPSI */
#define GUID_DECAUTH	"DECAUTH"	/* decAuth */
#define GUID_ZANNET		"ZANNET"	/* ZanNet */
#define GUID_PKIXTS		"PKIXTS"	/* PKIX TimeStamp */
#define GUID_PTP		"PTP"		/* Precision Time Protocol */
#define GUID_PIP		"PIP"		/* Private IP */
#define GUID_RTSPS		"RTSPS"		/* Real Time Streaming Protocol Security */
#define GUID_TEXAR		"TEXAR"		/* Texar */
#define GUID_PDAP		"PDAP"		/* Prospero Data Access Protocol */
#define GUID_PAWSERV	"PAWSERV"	/* Perf Analysis Workbench */
#define GUID_ZEBRA		"ZEBRA"		/* Zebra Server */
#define GUID_FATMEN		"FATMEN"	/* Fatmen Server */
#define GUID_CSISGWP	"CSISGWP"	/* Cabletron Management Protocol */
#define GUID_MFTP		"MFTP"		/* Multisource File Transfer Protocol */
#define GUID_MATIP		"MATIP"		/* Mapping of Airline Reservation, and Ticketing over IP */
#define GUID_DTAG		"DTAG"		/* DTAG */
#define GUID_NDSAUTH	"NDSAUTH"	/* NDSauth */
#define GUID_BH611		"BH611"		/* Bell_and_Howell */
#define GUID_DATEXASN	"DATEXASN"	/* DATEX-ASN */
#define GUID_CLOANTO	"CLOANTO"	/* Cloanto Net One */
#define GUID_BHEVENT	"BHEVENT"	/* bhevent */
#define GUID_SHRNKRAP	"SHRNKRAP"	/* Shrinkwrap */
#define GUID_NSRMP		"NSRMP"		/* Network Security Risk Management Protocol */
#define GUID_SCOI2DLG	"SCOI2DLG"	/* scoi2odialog */
#define GUID_SEMANTIX	"SEMANTIX"	/* Semantix */
#define GUID_SRSSEND	"SRSSEND"	/* SRS Send */
#define GUID_RSVPTUNN	"RSVPTUNN"	/* RSVP Tunnel */
#define GUID_AURORA		"AURORA"	/* Aurora */
#define GUID_DTK		"DTK"		/* DTK */
#define GUID_ODMR		"ODMR"		/* On-Demand Mail Relay */
#define GUID_MRTGWARE	"MRTGWARE"	/* MortgageWare */
#define GUID_QBIK		"QBIK"		/* Qbik */
#define GUID_RPC2PMAP	"RPC2PMAP"	/* RPC To Portmap */
#define GUID_CODAAUTH	"CODAAUTH"	/* Coda authentication */
#define GUID_CLRCASE	"CLRCASE"	/* Clearcase */
#define GUID_ULSTPROC	"ULSTPROC"	/* ListProcessor */
#define GUID_LEGENT		"LEGENT"	/* Legent Corporation */
#define GUID_HASSLE		"HASSLE"	/* Hassle */
#define GUID_NIP		"NIP"		/* Amiga Envoy Network Inquiry Proto */
#define GUID_ETOS		"ETOS"		/* NEC Corporation */
#define GUID_IS99		"IS99"		/* TIA/EIA/IS-99 modem */
#define GUID_HPPERF		"HPPERF"	/* hp performance data */
#define GUID_ARNS		"ARNS"		/* A Remote Network Server System */
#define GUID_IBMAPP		"IBMAPP"	/* IBM Application */
#define GUID_ASA		"ASA"		/* ASA Message Router */
#define GUID_UDLDM		"UDLDM"		/* Unidata LDM */
#define GUID_LDAP		"LDAP"		/* Lightweight Directory Access Protocol */
#define GUID_UIS		"UIS"		/* UIS */
#define GUID_SYNOTICS	"SYNOTICS"	/* SynOptics */
#define GUID_META5		"META5"		/* Meta5 */
#define GUID_EMBLNDT	"EMBLNDT"	/* EMBL Nucleic Data Transfer */
#define GUID_NETSCOUT	"NETSCOUT"	/* NetScout Control Protocol */
#define GUID_NETWARE	"NETWARE"	/* Novell Netware over IP */
#define GUID_MPTN		"MPTN"		/* Multi Protocol Trans. Net. */
#define GUID_KRYPTLAN	"KRYPTLAN"	/* Kryptolan */
#define GUID_ORACLE		"ORACLE"	/* Oracle */
#define GUID_UPS		"UPS"		/* Uninterruptible Power Supply */
#define GUID_GENIE		"GENIE"		/* Genie Protocol */
#define GUID_DCAP		"DCAP"		/* decap */
#define GUID_NCED		"NCED"		/* nced */
#define GUID_NCLD		"NCLD"		/* ncld */
#define GUID_IMSP		"IMSP"		/* Interactive Mail Support Protocol */
#define GUID_TIMBUKTU	"TIMBUKTU"	/* Timbuktu */
#define GUID_DECDEBUG	"DECDEBUG"	/* DECLadebug Remote Debug Protocol */
#define GUID_RMT		"RMT"		/* Remote MT Protocol */
#define GUID_SMSP		"SMSP"		/* Storage Management Services Protocol */
#define GUID_INFOSEEK	"INFOSEEK"	/* InfoSeek */
#define GUID_BNET		"BNET"		/* BNet */
#define GUID_SLVRPLTR	"SLVRPLTR"	/* Silverplatter */
#define GUID_ONMUX		"ONMUX"		/* Onmux */
#define GUID_HYPERG		"HYPERG"	/* Hyper-G */
#define GUID_ARIEL		"ARIEL"		/* Ariel */
#define GUID_SMPTE		"SMPTE"		/* SMPTE */
#define GUID_IBMOPC		"IBMOPC"	/* IBM Operations Planning and Control */
#define GUID_ICAD		"ICAD"		/* ICAD */
#define GUID_SMARTSDP	"SMARTSDP"	/* smartsdp */
#define GUID_SVRLOC		"SVRLOC"	/* Server Location */
#define GUID_OCS		"OCS"		/* Office Communications Server */
#define GUID_UTMP		"UTMP"		/* UTMP */
#define GUID_IASD		"IASD"		/* IASD */
#define GUID_NNSP		"NNSP"		/* Net News Transfer Protocol */
#define GUID_MOBILIP	"MOBILIP"	/* MobileIP */
#define GUID_DNACML		"DNACML"	/* DNA-CML */
#define GUID_COMSCM		"COMSCM"	/* com SCM Microsystems, Inc. */
#define GUID_DSFGW		"DSFGW"		/* DSFGW */
#define GUID_DASP		"DASP"		/* Datagram Authenticated Session Protocol */
#define GUID_SGCP		"SGCP"		/* Simple Gateway Control Protocol */
#define GUID_DECVMS		"DECVMS"	/* decvms-sysmgt */
#define GUID_CVCHOSTD	"CVCHOSTD"	/* cvc hostd */
#define GUID_SSL		"SSL"		/* Secure Sockets Layer */
#define GUID_SNPP		"SNPP"		/* Simple Network Paging Protocol */
#define GUID_CIFS		"CIFS"		/* Common Internet File System */
#define GUID_QUICKTIM	"QUICKTIM"	/* Apple Quick Time */
#define GUID_RIP		"RIP"		/* Routing Information Protocol */
#define GUID_RTSP		"RTSP"		/* Real Time Streaming Protocol */
#define GUID_AFP		"AFP"		/* Apple Filing Protocol */
#define GUID_ISAKMP		"ISAKMP"	/* Internet Security Association and Key Mgt Protocol */
#define GUID_CRS		"CRS"		/* MS Content Replication Server */
#define GUID_PRINTER	"PRINTER"	/* Internet Printing Protocol */
#define GUID_FILEMAKR	"FILEMAKR"	/* FileMaker, Inc. */
#define GUID_RRP		"RRP"		/* NSI Registry Registrar Protocol */
#define GUID_CORBA		"CORBA"		/* CORBA IIOP */
#define GUID_RSYNC		"RSYNC"		/* Rsync */
#define GUID_JAVARMI	"JAVARMI"	/* Java Remote Method Invocation */
#define GUID_SYBASE		"SYBASE"	/* Sybase SQL Any */
#define GUID_DHCPV6		"DHCPV6"	/* Dynamic Host Configuration Protocol for IPv6 */

/* IANA registered */
#define GUID_PFTP		"PFTP"		/* Port-File-Transfer-Program */
#define GUID_FTPSDATA	"FTPSDATA"	/* FTP data over TLS/SSL */
#define GUID_FTPS		"FTPS"		/* FTP control over TLS/SSL */
#define GUID_GSIFTP		"GSIFTP"	/* FTP enhanced to use GSI security */
#define GUID_OFTP		"OFTP"		/* Odette File Transfer Protocol */
#define GUID_TFTPS		"TFTPS"		/* Trivial File Transfer Protocol over SSL/TLS */
#define GUID_OFTPS		"OFTPS"		/* Odette FTP over SSL/TLS */
#define GUID_KFTPDATA	"KFTPDATA"	/* Kerberos FTP data */
#define GUID_KFTP		"KFTP"		/* Kerberos FTP control */
#define GUID_MCFTP		"MCFTP"		/* Multicast FTP */
#define GUID_KTELNET	"KTELNET"	/* Kerberos Telnet */
#define GUID_BLCKJACK	"BLCKJACK"	/* Network Blackjack */
#define GUID_CAP		"CAP"		/* Calendar Access Protocol */
#define GUID_NETINFO	"NETINFO"	/* Local Netinfo port */
#define GUID_ACTVSYNC	"ACTVSYNC"	/* ActiveSync Notifications */
#define GUID_NSSTP		"NSSTP"		/* Nebula Secure Segment Transfer Protocol */
#define GUID_WEBFLTR	"WEBFLTR"	/* WebFilter Remote Monitor */
#define GUID_IMGAMES	"IMGAMES"	/* IMGames */
#define GUID_AVCTPRXY	"AVCTPRXY"	/* Avocent Proxy Protocol */
#define GUID_SOCKS		"SOCKS"		/* SOCKS server */
#define GUID_ICP		"ICP"		/* Intelligent Communication Protocol */
#define GUID_MINISQL	"MINISQL"	/* Mini SQL */
#define GUID_BATTLNET	"BATTLNET"	/* Battle.net Chat/Game Protocol */
#define GUID_HPVMM		"HPVMM"		/* HP VMM Control/Agent */
#define GUID_KWDB		"KWDB"		/* KWDB Remote Communication */
#define GUID_SAP		"SAP"		/* SAPHostControl over SOAP */
#define GUID_KVM		"KVM"		/* KVM-via-IP Management Service */
#define GUID_BLAZEFS	"BLAZEFS"	/* Blaze File Server */
#define GUID_NFA		"NFA"		/* Network File Access */
#define GUID_COMVAULT	"COMVAULT"	/* Commvault */
#define GUID_CSCOSLA	"CSCOSLA"	/* Cisco IP SLAs Control Protocol */
#define GUID_VCHAT		"VCHAT"		/* VChat Video Conferencing */
#define GUID_TRIPWIRE	"TRIPWIRE"	/* Tripwire */
#define GUID_MYSQL		"MYSQL"		/* MySQL */
#define GUID_ALIAS		"ALIAS"		/* Alias Service */
#define GUID_GPFS		"GPFS"		/* IBM General Parallel File System */
#define GUID_OPENVPN	"OPENVPN"	/* OpenVPN */
#define GUID_KAZAA		"KAZAA"		/* Kazaa P2P */
#define GUID_SHOCKWAV	"SHOCKWAV"	/* Shockwave Multimedia Player */
#define GUID_IPSEC		"IPSEC"		/* Internet Protocol Security */
#define GUID_H323		"H323"		/* H323 Specification */
#define GUID_ISCHAT		"ISCHAT"	/* Instant Service Chat */
#define GUID_MSSQL		"MSSQL"		/* Microsoft SQL */
#define GUID_CTRXICA	"CTRXICA"	/* Citrix ICA */
#define GUID_CTRXIMA	"CTRXIMA"	/* Citrix IMA */
#define GUID_CTRXCGP	"CTRXCGP"	/* Citrix CGP */
#define GUID_L2TP       "L2TP"		/* Layer 2 Tunneling Protocol */
#define GUID_SSDP		"SSDP"		/* Simple Service Discovery Protocol */
#define GUID_NFS		"NFS"		/* Network File System Protocol */
#define GUID_WANSCALR	"WANSCALR"	/* Citrix WAN Scaler */
#define GUID_CTRXRTMP	"CTRXRTMP"	/* Citrix RTMP */
#define GUID_RTMP		"RTMP"		/* Real Time Messaging Protocol */
#define GUID_RDP		"RDP"		/* Remote Desktop Protocol */
#define GUID_HIVESTOR	"HIVESTOR"	/* HiveStor */
#define GUID_SIP		"SIP"		/* Session Initiation Protocol */
#define GUID_LLMNR		"LLMNR"		/* Link-local Multicast Name Resolution */
#define GUID_POSTGRES	"POSTGRES"	/* Postgres */
#define GUID_CTRXLIC	"CTRXLIC"	/* Citrix Licensing */
#define GUID_SHOUTCAS	"SHOUTCAS"	/* Shoutcast */
#define GUID_MDNS		"MDNS"		/* Multicast DNS */
#define GUID_CTRXSLGW	"CTRXSLGW"	/* Citrix StorageLink Gateway */
#define GUID_SYSLOG		"SYSLOG"	/* System information logging service */
#define GUID_RADIUS		"RADIUS"	/* Remote Authentication Dial In User Service */
#define GUID_GRPWISE	"GRPWISE"	/* Novell Groupwise */
#define GUID_PPTP		"PPTP"		/* Point-to-point Tunneling Protocol */
#define GUID_MSMQ		"MSMQ"		/* Microsoft Message Queue */
#define GUID_CSCODRP	"CSCODRP"	/* Cisco Director Response Protocol */
#define GUID_CSCOGDP	"CSCOGDP"	/* Cisco Gateway Discovery Protocol */
#define GUID_MEETMAKR	"MEETMAKR"	/* Meeting Maker */
#define GUID_MSOLAP		"MSOLAP"	/* Microsoft OLAP */
#define GUID_HL7		"HL7"		/* Health Level 7 Medical informatin xchange */
#define GUID_IVPIP		"IVPIP"		/* mck, now citel, ivpip */
#define GUID_H248		"H248"		/* Megaco H-248 */
#define GUID_XBOX		"XBOX"		/* Xbox game console traffic */
#define GUID_SCURSGHT	"SCURSGHT"	/* SecurSight */

/* Higher Layer / Non-registered */
#define GUID_RTP		"RTP"		/* Real-Time Transport Protocol */
#define GUID_RTCP		"RTCP"		/* Real-Time Transport Control Protocol */
#define GUID_MSBITS		"MSBITS"	/* Microsoft Background Intelligent Transfer Service */
#define GUID_BITTORRE	"BITTORRE"	/* BitTorrent client */
#define GUID_CTRXONLN	"CTRXONLN"	/* Citrix Online */
#define GUID_CTRXJEDI	"CTRXJEDI"	/* Citrix Jedi */
#define GUID_CRAIGSLI	"CRAIGSLI"	/* Craigs List */
#define GUID_GOOGLE		"GOOGLE"	/* Google */
#define GUID_GMAIL		"GMAIL"		/* Google Email Service */
#define GUID_GOOGERTH	"GOOGERTH"	/* Google Earth */
#define GUID_GOOGVIDO	"GOOGVIDO"	/* Google Video */
#define GUID_GOOGCNDR	"GOOGCNDR"	/* Google Calendar */
#define GUID_GOOGDOCS	"GOOGDOCS"	/* Google Documents */
#define GUID_GOOGDESK	"GOOGDESK"	/* Google Desktop */
#define GUID_GTALKGAD	"GTALKGAD"	/* Google Talk Gadget */
#define GUID_GOOGTRAN	"GOOGTRAN"	/* Google Translate */
#define GUID_GOOGANAL	"GOOGANAL"	/* Google Analytics */
#define GUID_GOOGAPIS	"GOOGAPIS"	/* Google APIs */
#define GUID_GOOGSAFE	"GOOGSAFE"	/* Google Safe Browsing API */
#define GUID_GOOGAPP	"GOOGAPP"	/* Google App Engine */
#define GUID_GOTOMEET	"GOTOMEET"	/* GoToMeeting Online Meeting */
#define GUID_AUDIO		"AUDIO"		/* Http Audio Content */
#define GUID_VIDEO		"VIDEO"		/* Http Video Content */
#define GUID_ITUNES		"ITUNES"	/* Apple iTunes */
#define GUID_METACAFE	"METACAFE"	/* Metacafe Online Video */
#define GUID_MSNP		"MSNP"		/* MSN Protocol */
#define GUID_GIGANEWS	"GIGANEWS"	/* Giganews */
#define GUID_ASTRAWEB	"ASTRAWEB"	/* Astraweb */
#define GUID_USENET		"USENET"	/* Usenet */
#define GUID_SUPRNEWS	"SUPRNEWS"	/* SuperNews */
#define GUID_SALSFRCE	"SALSFRCE"	/* Salesforce */
#define GUID_MAGICJAK	"MAGICJAK"	/* Magic Jack VOIP */
#define GUID_VONAGE		"VONAGE"	/* Vonage VOIP */
#define GUID_TMOBILE	"TMOBILE"	/* TMobile Telecommunications */
#define GUID_YAHOO		"YAHOO"		/* Yahoo */
#define GUID_WIKIPEDI	"WIKIPEDI"	/* Wikipedia */
#define GUID_EBAY		"EBAY"		/* Ebay */
#define GUID_BING		"BING"		/* Bing Search Engine */
#define GUID_HOTMAIL	"HOTMAIL"	/* Hotmail Email Service */
#define GUID_SKYDRIVE	"SKYDRIVE"	/* SkyDrive Online Storage */
#define GUID_WINLIVE	"WINLIVE"	/* Windows Live */
#define GUID_MSN		"MSN"		/* Microsoft Network */
#define GUID_FOGBUGZ	"FOGBUGZ"	/* Fogbugz Bug Tracking */
#define GUID_AMAZON		"AMAZON"	/* Amazon */
#define GUID_ZOHO		"ZOHO"		/* Zoho */
#define GUID_SKYPE		"SKYPE"		/* Skype */
#define GUID_FACEBOOK	"FACEBOOK"	/* Facebook */
#define GUID_MYSPACE	"MYSPACE"	/* Myspace */
#define GUID_TWITTER	"TWITTER"	/* Twitter */
#define GUID_LINKEDIN	"LINKEDIN"	/* LinkedIn */
#define GUID_FRNDSTER	"FRNDSTER"	/* Friendster */
#define GUID_STUN		"STUN"		/* Session Traversal Utilities for NAT */
#define GUID_WEBEX		"WEBEX"		/* WebEx Online Meetings */
#define GUID_WINMEDIA	"WINMEDIA"	/* Windows Media */
#define GUID_YOUTUBE	"YOUTUBE"	/* YouTube */
#define GUID_MSONLINE	"MSONLINE"	/* Microsoft Online Services */
#define GUID_LIVEMEET	"LIVEMEET"	/* Live Meeting Online Meetings */
#define GUID_FARMVILE	"FARMVILE"	/* Farmville Game */
#define GUID_MAFIAWAR	"MAFIAWAR"	/* Mafiawars Game */
#define GUID_ZYNGAGAM	"ZYNGAGAM"	/* Zynga Games */
#define GUID_FBOOKAPP	"FBOOKAPP"	/* Facebook Application */
#define GUID_WINNY		"WINNY"		/* WinNY P2P */
#define GUID_GNUTELLA	"GNUTELLA"	/* Gnutella File Sharing */
#define GUID_AOL_IM		"AOL_IM"	/* AOL Instant Messenger */
#define GUID_XMPP     	"XMPP"		/* Extensible Messaging and Presence Protocol */
#define GUID_GTALK    	"GTALK"		/* Google Talk */
#define GUID_YMSG		"YMSG"		/* Yahoo! messenger */
#define GUID_MEGAUPLD 	"MEGAUPLD"	/* MegaUpload */
#define GUID_BACKBLZE 	"BACKBLZE"	/* BackBlaze */
#define GUID_FILESTBE 	"FILESTBE"	/* FilesTube */
#define GUID_HOTFILE  	"HOTFILE"	/* Hotfile File Sharing */
#define GUID_RAPSHARE 	"RAPSHARE"	/* RapidShare */
#define GUID_MEDIAFRE 	"MEDIAFRE"	/* MediaFire */
#define GUID_DROPBOX	"DROPBOX"	/* Dropbox filesharing */
#define GUID_MSDN		"MSDN"		/* MSDN subscriber downloads */
#define GUID_SHRPOINT	"SHRPOINT"	/* Microsoft Sharepoint */
#define GUID_H225		"H225"		/* H.225 Protocol */
#define GUID_H245		"H245"		/* H.245 Protocol */
#define GUID_NOTES		"NOTES"		/* Lotus Notes */
#define GUID_DCERPC		"DCERPC"	/* DCE/RPC traffic */
#define GUID_EXCHANGE	"EXCHANGE"	/* MS Exchange */
#define GUID_MAPI		"MAPI"		/* Exchange MAPI*/
#define GUID_RFR		"RFR"		/* Exchange Referral Interface */
#define GUID_STORADMN	"STORADMN"	/* Exchange STORE ADMIN */
#define GUID_MTA		"MTA"		/* Exchange Mail Transfer Agent */
#define GUID_INFOSTOR	"INFOSTOR"	/* Exchange Information Store */
#define GUID_SYSATT		"SYSATT"	/* Exchange System Attendent Services */
#define GUID_NETLOGON	"NETLOGON"	/* MS Netlogon service */
#define GUID_ACTIVDIR	"ACTIVDIR"  /* Active Directory (AD)*/
#define GUID_LSARPC		"LSARPC"	/* Local Security Authority */
#define GUID_SAMR		"SAMR"		/* Security Account Manager */
#define GUID_DSSETUP	"DSSETUP"	/* Directory Services Setup */
#define GUID_ADBKUP		"AD_BKUP"	/* AD Backup */
#define GUID_ADRSTOR	"AD_RSTOR"	/* AD Restore */
#define GUID_DSROLE		"AD_DSROL"	/* AD Domain Services role */
#define GUID_DSAOP		"AD_DSAOP"	/* AD Domain Services aop */
#define GUID_DRS		"AD_DRS"	/* AD Directory Replication Service */
#define GUID_XDS		"AD_XDS"	/* AD Extended Directory Service */
#define GUID_NSP		"AD_NSP"	/* AD Name Service Provider */
#define GUID_PHOTOBKT	"PHOTOBKT"	/* Photobucket photo/video sharing site */
#define GUID_FLICKR		"FLICKR"	/* Flickr photo sharing */
#define GUID_PICASA		"PICASA"	/* Google picasa */
#define GUID_BEBO		"BEBO"		/* Social networking site www.bebo.com */
#define GUID_BLOGGER	"BLOGGER"	/* Google blogger - formerly blogspot */
#define GUID_DALYMOTN	"DALYMOTN" /* Dailymotion social networking video site */
#define GUID_LASTFM		"LASTFM"	/* Last.fm social networking music site */
#define GUID_LIVEJRNL	"LIVEJRNL"	/* LiveJournal blogging community */
#define GUID_TUMBLR		"TUMBLR"	/* Tumblr blogging community */
#define GUID_WRDPRESS	"WRDPRESS"	/* Wordpress blogging community */
#define GUID_XANGA		"XANGA"		/* Xanga blogging community */
#define GUID_ICQ		"ICQ"		/* ICQ messenger */
#define GUID_AVG		"AVG"		/* AVG AV/Security */
#define GUID_AVIRA		"AVIRA"		/* Avira AV/Security */
#define GUID_BDEFNDER	"BDEFNDER"	/* BitDefender AV/Security */
#define GUID_ESET		"ESET"		/* Eset AV/Security */
#define GUID_FPROT		"FPROT"		/* F-Prot AV/Security */
#define GUID_KASPRSKY	"KASPRSKY"	/* Kaspersky AV/Security */
#define GUID_MCAFEE		"MCAFEE"	/* McAfee AV/Security */
#define GUID_PANDA		"PANDA"		/* Panda Security AV/Security */
#define GUID_ADOBE		"ADOBE"		/* Adobe */
#define GUID_QQ			"QQ"		/* QQ protocol - Chinese IM */
#define GUID_OSCAR		"OSCAR"		/* AOL's OSCAR im protocol */
#define GUID_4SHARED	"4SHARED"	/* 4Shared online file upload service */
#define GUID_FILERCX	"FILERCX"	/* filer.cx online file upload service */
#define GUID_YOUSNDIT	"YOUSNDIT"	/* YouSendIt online file hosting and transfer service */
#define GUID_PLAXO		"PLAXO"		/* Plaxo online address book and contact storage service */
#define GUID_FLIXSTER	"FLIXSTER"	/* Flixster online movie review and social networking */
#define GUID_NETMEETG	"NETMEETG"	/* Microsoft NetMeeting */
#define GUID_STMBLUPN	"STMBLUPN"	/* Stumble Upon web traffic engine */
#define GUID_HOPSTER	"HOPSTER"	/* Hopster web anonymizer */
#define GUID_SKYPEOUT	"SKYPEOUT"	/* Skype to PSTN */
#define GUID_SKYPAUTH	"SKYPAUTH"	/* Skype Authentication */
#define GUID_SKYPROBE	"SKYPROBE"	/* Skype Discovery Probes */
#define GUID_SKYPEP2P	"SKYPEP2P"	/* Skype Peer-to-Peer */
#define GUID_MEEBO		"MEEBO"		/* Meebo Messaging Service */
#define GUID_WEBDAV		"WEBDAV"	/* Web distributed authering */
#define GUID_LOGMEIN	"LOGMEIN"	/* LogMeIn remote access application */
#define GUID_HULU		"HULU"		/* Hulu video streaming */
#define GUID_FRNDFEED	"FRNDFEED"	/* FriendFeed social networking website */
#define GUID_RSS		"RSS"		/* Really Simple Syndication */
#define GUID_ATOM		"ATOM"		/* Atom Syndication Format */
#define GUID_FASP		"FASP"		/* Fast and Secure Protocol - Aspera Inc. */
#define GUID_TOR		"TOR"		/* Tor anonymous routing service */
#define GUID_USTREAM	"USTREAM"	/* UStream Interactive Broadcast Platform */
#define GUID_APPLEUPD	"APPLEUPD"	/* Apple Update Service */
#define GUID_YMSGFILE	"YMSGFILE"	/* Yahoo! Messenger File Transfer */
#define GUID_NETFLX		"NETFLX"	/* Netflix.com website */
#define GUID_NETFLXVD	"NETFLXVD"	/* Netflix video streaming */
#define GUID_ORKUT	"ORKUT"		/* Google orkut social network */
#define GUID_SHAREP2P	"SHAREP2P"	/* Japanese P2P application */
#define GUID_REDDIT		"REDDIT"	/* Reddit social news aggregator */
#define GUID_IMGUR		"IMGUR"		/* Annonymous free image host */
#define GUID_GRVSHRK	"GRVSHRK"	/* Grooveshark Music streaming */
#define GUID_YELP		"YELP"		/* Yelp.com Online social business directory */
#define GUID_DOCSTOC	"DOCSTOC"	/* Docstoc Document sharing */
#define GUID_BINGBOT	"BINGBOT"	/* Bingbot web crawler */
#define GUID_YHOOSLRP	"YHOOSLRP"	/* Yahoo! Slurp web crawler */
#define GUID_GOOGLBT	"GOOGLBT"	/* Googlebot Web Crawler */
#define GUID_EDONKEY	"EDONKEY"	/* eDonkey/eMesh p2p protocol */
#define GUID_IMESH		"IMESH"		/* iMesh media p2p file sharing */
#define GUID_TEAMVIEW	"TEAMVIEW"	/* Teamviewer Remote Desktop Protocol*/
#define GUID_MANOLITO	"MANOLITO"	/* Manolito P2P Protocol */
#define GUID_PANDO		"PANDO"		/* Pando P2P File Distribution */
#define GUID_WINMX		"WINMX"		/* WinMX P2P Protocol */
#define GUID_PT         "PT"        /* Paltalk Instant Messaging application */
#define GUID_PT_CHAT    "PT_CHAT"   /* Paltalk Instant Messaging*/
#define GUID_PT_VOICE   "PT_VOICE"  /* Voice chat using Paltalk*/
#define GUID_PT_VIDEO   "PT_VIDEO"  /* Video chat using Paltalk*/
#define GUID_PT_FILE    "PT_FILE"   /* Paltalk file transfer*/
#define GUID_APPLJUCE   "APPLJUCE"  /* Apple Juice P2P file sharing */
#define GUID_APPLGUI    "APPLGUI"   /* Apple Juice GUI to Core communication */
#define GUID_WINUPDAT   "WINUPDAT"  /* Microsoft Windows Update */
#define GUID_GOOGPLUS   "GOOGPLUS"  /* Google Plus Social Netoworking Site */
#define GUID_MUTENET    "MUTENET"   /* MUTE Net p2p anonymous file sharing */
#define GUID_SHOWMYPC	"SHOWMYPC"  /* SHOWMYPC remote desktop connection*/
#define GUID_TWITPIC    "TWITPIC"   /* Twitpic */
#define GUID_XUNLEI		"XUNLEI"	/* Xunlei p2p application */
#define GUID_PRIVAX		"PRIVAX"	/* Privax web proxies */
#define GUID_SCCM		"SCCM"		/* Microsoft System Center Configuration Manager */
#define GUID_SCCMCTRL	"SCCMCTRL"	/* Micorosft System Center Remote Control */
#define GUID_WHATSAPP	"WHATSAPP"	/* Whatsapp free texting / messaging Application */
#define GUID_STEAM		"STEAM"		/* Steam Game Distribution */
#define GUID_STEAMDLC	"STEAMDLC"	/* Steam Downloads (games/client updates) */
#define GUID_STEAMGME	"STEAMGME"	/* Steam Online Game Play */
#define GUID_STEAMCLI	"STEAMCLI"	/* Steam Client Web access */
#define GUID_STEAMSOC	"STEAMSOC"	/* Steam Social Networking */
#define GUID_DYNGATE	"DYNGATE"	/* NAT traversal tunnel Dyngate - used by Teamviewer */
#define GUID_PINGER	"PINGER"	/* Pinger text and voice service */
#define GUID_LINE2	"LINE2"		/* Line2 messaging application */
#define GUID_DRCTCONN	"DRCTCONN"	/* Direct Connect P2P Protocol */
#define GUID_HAMACHI    "HAMACHI"       /* LogMEIn Hamachi Virtual Private Network*/
#define GUID_GOOGMAPS   "GOOGMAPS"  	/* Google maps */
#define GUID_C2DM       "C2DM"		/* Cloud to Device Messaging (Android push notifications) */
#define GUID_APNS		"APNS"		/* Apple Push Notification Service */
#define GUID_ICLOUD		"ICLOUD"	/* Apple Cloud Services */
#define GUID_APPLE		"APPLE"		/* Apple website */
#define GUID_FACETIME	"FACETIME" 	/* Apple iOS Facetime video calling */
#define GUID_PCOIP		"PCOIP"		/* Teradici PCoIP remote desktop protocol */
#define GUID_PANDORA	"PANDORA"	/* Pandora Internet radio streaming */
#define GUID_PNDRAUDI	"PNDRAUDI"	/* Pandora Audio */
#define GUID_ABOUT	"ABOUT"	/* Source for original information and advice */
#define GUID_ANSWERS	"ANSWERS"	/* Internet based knowledge exchange */
#define GUID_BARNSNBL	"BARNSNBL"	/* Book, DVD, toy, and music marketplace */
#define GUID_BIGUPLOD	"BIGUPLOD"	/* Secure uploading, transferring and filesharing */
#define GUID_CLASSMTE	"CLASSMTE"	/* High-school oriented social network */
#define GUID_CNET	"CNET"	/* Tech media website */
#define GUID_CNETDWLD	"CNETDWLD"	/* CNET focused on software downloads */
#define GUID_DELL	"DELL"	/* Official DELL website */
#define GUID_DOMNTOOL	"DOMNTOOL"	/* Internet domain name intelligence service */
#define GUID_HP	"HP"	/* Official HP website */
#define GUID_IBM	"IBM"	/* Official IBM website */
#define GUID_ISOHUNT	"ISOHUNT"	/* Torrent repository */
#define GUID_MEGASHRS	"MEGASHRS"	/* File sharing and media streaming */
#define GUID_MOVIE2K	"MOVIE2K"	/* Media linking */
#define GUID_MULTIPLY	"MULTIPLY"	/* Social shopping */
#define GUID_MULTUPLD	"MULTUPLD"	/* File transfer and storage website */
#define GUID_OPENWEBM	"OPENWEBM"	/* Webmail*/
#define GUID_SLIDESHR	"SLIDESHR"	/* Slide hosting service */
#define GUID_SRCFORGE	"SRCFORGE"	/* Online source code repository */
#define GUID_SURVMONK	"SURVMONK"	/* Custom web-survey creation */
#define GUID_TORRENTZ	"TORRENTZ"	/* BitTorrent meta-search engine */
#define GUID_VIDEOBB	"VIDEOBB"	/* Video hosting */
#define GUID_W3SCHOOL	"W3SCHOOL"	/* Online Web Tutorials */
#define GUID_WEEBLY	"WEEBLY"	/* Custom website creation */
#define GUID_12306CN	"12306CN"	 /* Chinese Railway customer service center */
#define GUID_126COM	"126COM"	 /* Chinese webmail service */
#define GUID_39NET	"39NET"	 /* Chinese health web portal */
#define GUID_ADRIVE	"ADRIVE"	 /* Online cloud storage */
#define GUID_AIZHAN	"AIZHAN"	 /* Webmaster assistance */
#define GUID_BET365	"BET365"	 /* Online gambling website */
#define GUID_BRGHTTLK	"BRGHTTLK"	 /* Online webinar and video provider */
#define GUID_BROSOFT	"BROSOFT"	 /* Free software download website */
#define GUID_DEPOFILE	"DEPOFILE"	 /* File storage */
#define GUID_ENETCN	"ENETCN"	 /* Web portal for IT people */
#define GUID_ENVATO	"ENVATO"	 /* Web tutorial services */
#define GUID_EXTRTORR	"EXTRTORR"	 /* BitTorrent provider */
#define GUID_GLYPEPRX	"GLYPEPRX"	 /* Web proxy */
#define GUID_GOONEJP	"GOONEJP"	 /* Japanese web portal */
#define GUID_IMGVENUE	"IMGVENUE"	 /* Image hosting/sharing site */
#define GUID_KATORRNT	"KATORRNT"	 /* Torrent aggregator */
#define GUID_LEBNCOIN	"LEBNCOIN"	 /* French sales website */
#define GUID_MSN2GO	"MSN2GO"	 /* Internet alternative to MSN messenger */
#define GUID_NETEASE	"NETEASE"	 /* Chinese web portal */
#define GUID_ONLINEFF	"ONLINEFF"	 /* Online file storage */
#define GUID_PUTLOCKR	"PUTLOCKR"	 /* Online file storage */
#define GUID_RGINBULL	"RGINBULL"	 /* Financial investment website */
#define GUID_SOKU	"SOKU"	 /* Chinese web portal and search engine */
#define GUID_THEMFRST	"THEMFRST"	 /* Website template marketplace */
#define GUID_WEBSCOM	"WEBSCOM"	 /* Website creation */
#define GUID_WYSE_TCX	"WYSE_TCX"	/* Wyse TCX */
#define GUID_TCXFLASH	"TCXFLASH"	/* Wyse TCX Flash Redirection */
#define GUID_TCXMEDIA	"TCXMEDIA"	/* Wyse TCX Multimedia Redirection */
#define GUID_TCXUSB		"TCXUSB"	/* Wyse TCX USB Redirection */
#define GUID_TCXSOUND	"TCXSOUND"	/* Wyse TCX Rich Sound */

#define GUID_4399COM	"4399COM"	/* Chinese gaming site */
#define GUID_ADFLY	"ADFLY"	/* URL shortener service */
#define GUID_ADMIN5	"ADMIN5"	/* Webmaster information */
#define GUID_BLOOMBRG	"BLOOMBRG"	/* Business and Finance news */
#define GUID_DATEITO	"DATEITO"	/* File hosting website */
#define GUID_DIVSHARE	"DIVSHARE"	/* File sharing website */
#define GUID_FILESONC	"FILESONC"	/* Cloud storage */
#define GUID_IMGSHACK	"IMGSHACK"	/* Free image hosting website */
#define GUID_MOZILLA	"MOZILLA"	/* Not-for-profite internet collective */
#define GUID_PINTERST	"PINTERST"	/* Social media sharing website */
#define GUID_SURESOME	"SURESOME"	/* HTTPS web proxy */
#define GUID_SUROGAFR	"SUROGAFR"	/* Web proxy */
#define GUID_WRETCH	"WRETCH"	/* Taiwanese community website */
#define GUID_Y8		"Y8"	/* Flash gaming */
#define GUID_FB_SRCH	"FB_SRCH"	/* Facebook Search Query */
#define GUID_FB_EVENT	"FB_EVENT"	/* Facebook Event */
#define GUID_FB_POST	"FB_POST"	/* Facebook Wall Post */
#define GUID_FB_VDCHT	"FB_VDCHT"	/* Facebook Video Chat */
#define GUID_FB_MSGS	"FB_MSGS"	/* Facebook Messages (Chat and Email) */
#define GUID_FB_VIDEO	"FB_VIDEO"	/* Facebook Video */


#ifdef __cplusplus
}
#endif

#endif
