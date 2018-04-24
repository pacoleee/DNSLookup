package ca.ubc.cs.cs317.dnslookup;

import javax.annotation.Resource;
import java.io.ByteArrayOutputStream;
import java.io.Console;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.*;
import java.util.*;

public class DNSLookupService {

    private static final int DEFAULT_DNS_PORT = 53;
    private static final int MAX_INDIRECTION_LEVEL = 10;

    private static InetAddress rootServer;
    private static InetAddress rootOriginalServer;
    private static boolean verboseTracing = false;
    private static DatagramSocket socket;

    private static DNSCache cache = DNSCache.getInstance();

    private static Random random = new Random();

    private static int byteNo = 0;

    private static List<ResourceRecord> answersResourceRecords;
    private static List<ResourceRecord> nsResourceRecords;
    private static List<ResourceRecord> additionalResourceRecords;

    private static byte[] dnsQuery;

    /**
     * Main function, called when program is first invoked.
     *
     * @param args list of arguments specified in the command line.
     */
    public static void main(String[] args) {

        if (args.length != 1) {
            System.err.println("Invalid call. Usage:");
            System.err.println("\tjava -jar DNSLookupService.jar rootServer");
            System.err.println("where rootServer is the IP address (in dotted form) of the root DNS server to start the search at.");
            System.exit(1);
        }

        try {
            rootServer = InetAddress.getByName(args[0]);
            rootOriginalServer = rootServer;
            System.out.println("Root DNS server is: " + rootServer.getHostAddress());
        } catch (UnknownHostException e) {
            System.err.println("Invalid root server (" + e.getMessage() + ").");
            System.exit(1);
        }

        try {
            socket = new DatagramSocket();
            socket.setSoTimeout(5000);
        } catch (SocketException ex) {
            ex.printStackTrace();
            System.exit(1);
        }

        Scanner in = new Scanner(System.in);
        Console console = System.console();
        do {
            // Use console if one is available, or standard input if not.
            String commandLine;
            if (console != null) {
                System.out.print("DNSLOOKUP> ");
                commandLine = console.readLine();
            } else
                try {
                    commandLine = in.nextLine();
                } catch (NoSuchElementException ex) {
                    break;
                }
            // If reached end-of-file, leave
            if (commandLine == null) break;

            // Ignore leading/trailing spaces and anything beyond a comment character
            commandLine = commandLine.trim().split("#", 2)[0];

            // If no command shown, skip to next command
            if (commandLine.trim().isEmpty()) continue;

            String[] commandArgs = commandLine.split(" ");

            if (commandArgs[0].equalsIgnoreCase("quit") ||
                    commandArgs[0].equalsIgnoreCase("exit"))
                break;
            else if (commandArgs[0].equalsIgnoreCase("server")) {
                // SERVER: Change root nameserver
                if (commandArgs.length == 2) {
                    try {
                        rootServer = InetAddress.getByName(commandArgs[1]);
                        rootOriginalServer = rootServer;
                        System.out.println("Root DNS server is now: " + rootServer.getHostAddress());
                    } catch (UnknownHostException e) {
                        System.out.println("Invalid root server (" + e.getMessage() + ").");
                        continue;
                    }
                } else {
                    System.out.println("Invalid call. Format:\n\tserver IP");
                    continue;
                }
            } else if (commandArgs[0].equalsIgnoreCase("trace")) {
                // TRACE: Turn trace setting on or off
                if (commandArgs.length == 2) {
                    if (commandArgs[1].equalsIgnoreCase("on"))
                        verboseTracing = true;
                    else if (commandArgs[1].equalsIgnoreCase("off"))
                        verboseTracing = false;
                    else {
                        System.err.println("Invalid call. Format:\n\ttrace on|off");
                        continue;
                    }
                    System.out.println("Verbose tracing is now: " + (verboseTracing ? "ON" : "OFF"));
                } else {
                    System.err.println("Invalid call. Format:\n\ttrace on|off");
                    continue;
                }
            } else if (commandArgs[0].equalsIgnoreCase("lookup") ||
                    commandArgs[0].equalsIgnoreCase("l")) {
                // LOOKUP: Find and print all results associated to a name.
                RecordType type;
                if (commandArgs.length == 2)
                    type = RecordType.A;
                else if (commandArgs.length == 3)
                    try {
                        type = RecordType.valueOf(commandArgs[2].toUpperCase());
                    } catch (IllegalArgumentException ex) {
                        System.err.println("Invalid query type. Must be one of:\n\tA, AAAA, NS, MX, CNAME");
                        continue;
                    }
                else {
                    System.err.println("Invalid call. Format:\n\tlookup hostName [type]");
                    continue;
                }
                findAndPrintResults(commandArgs[1], type);
            } else if (commandArgs[0].equalsIgnoreCase("dump")) {
                // DUMP: Print all results still cached
                cache.forEachNode(DNSLookupService::printResults);
            } else {
                System.err.println("Invalid command. Valid commands are:");
                System.err.println("\tlookup fqdn [type]");
                System.err.println("\ttrace on|off");
                System.err.println("\tserver IP");
                System.err.println("\tdump");
                System.err.println("\tquit");
                continue;
            }

        } while (true);

        socket.close();
        System.out.println("Goodbye!");
    }

    /**
     * Finds all results for a host name and type and prints them on the standard output.
     *
     * @param hostName Fully qualified domain name of the host being searched.
     * @param type     Record type for search.
     */
    private static void findAndPrintResults(String hostName, RecordType type) {

        DNSNode node = new DNSNode(hostName, type);
        printResults(node, getResults(node, 0));
    }

    /**
     * Finds all the result for a specific node.
     *
     * @param node             Host and record type to be used for search.
     * @param indirectionLevel Control to limit the number of recursive calls due to CNAME redirection.
     *                         The initial call should be made with 0 (zero), while recursive calls for
     *                         regarding CNAME results should increment this value by 1. Once this value
     *                         reaches MAX_INDIRECTION_LEVEL, the function prints an error message and
     *                         returns an empty set.
     * @return A set of resource records corresponding to the specific query requested.
     */
    private static Set<ResourceRecord> getResults(DNSNode node, int indirectionLevel) {

        if (indirectionLevel > MAX_INDIRECTION_LEVEL) {
            rootServer = rootOriginalServer;
            System.err.println("Maximum number of indirection levels reached.");
            return Collections.emptySet();
        }

        // TODO To be completed by the student

        if (cache.getCachedResults(node).size() > 0) {
            rootServer = rootOriginalServer;
            return cache.getCachedResults(node);
        }


        retrieveResultsFromServer(node, rootServer);


        if (cache.getCachedResults(node).size() == 0) {
            if (answersResourceRecords.size() > 0 && answersResourceRecords.get(0).getType().equals(RecordType.CNAME)) {
                ResourceRecord currRecord = answersResourceRecords.get(0);
                Set<ResourceRecord> visitedRecords = new HashSet<>();
                visitedRecords.add(currRecord);
                while (true) {
                    Set<ResourceRecord> recordSet = cache.getCachedResults(new DNSNode(currRecord.getTextResult(), node.getType()));
                    if (recordSet.size() > 0) {
                        ResourceRecord temp = recordSet.iterator().next();
                        if (temp.getInetResult() != null) {
                            cache.addResult(new ResourceRecord(node.getHostName(),node.getType(), temp.getTTL(), temp.getInetResult()));
                        } else {
                            cache.addResult(new ResourceRecord(node.getHostName(),node.getType(), temp.getTTL(), temp.getTextResult()));
                        }
                        break;
                    } else {
                        Set<ResourceRecord> cnameSet = cache.getCachedResults(new DNSNode(currRecord.getTextResult(), RecordType.CNAME));
                        if (cnameSet.size() > 0) {
                            currRecord = cnameSet.iterator().next();
                            if (!visitedRecords.add(currRecord)) {
                                break;
                            }
                        } else {
                            rootServer = rootOriginalServer;
//                            return getResults(new DNSNode(currRecord.getTextResult(), node.getType()), indirectionLevel+1);
//                            System.out.println("hi");
                            for (ResourceRecord resourceRecord: getResults(new DNSNode(currRecord.getTextResult(), node.getType()), indirectionLevel+1)) {
                                if (resourceRecord.getInetResult() != null) {
                                    cache.addResult(new ResourceRecord(node.getHostName(),node.getType(), resourceRecord.getTTL(), resourceRecord.getInetResult()));
                                } else {
                                    cache.addResult(new ResourceRecord(node.getHostName(),node.getType(), resourceRecord.getTTL(), resourceRecord.getTextResult()));
                                }
                            }
                            break;
                        }
                    }
                }

            } else {
//                System.out.println(nsResourceRecords.size());
                for (int i = 0; i < nsResourceRecords.size(); i++) {
                    ResourceRecord record = nsResourceRecords.get(i);
                    Set<ResourceRecord> additionInfoA = cache.getCachedResults(new DNSNode(record.getTextResult(), RecordType.A));
                    if (additionInfoA.size() > 0) {
                        rootServer = additionInfoA.iterator().next().getInetResult();
                        Set<ResourceRecord> results = getResults(node, indirectionLevel+1);
                        for (ResourceRecord resourceRecord: results) {
                            if (resourceRecord.getInetResult() != null) {
                                cache.addResult(new ResourceRecord(node.getHostName(),node.getType(), resourceRecord.getTTL(), resourceRecord.getInetResult()));
                            } else {
                                cache.addResult(new ResourceRecord(node.getHostName(),node.getType(), resourceRecord.getTTL(), resourceRecord.getTextResult()));
                            }
                        }
                    } else {
                        if (i == nsResourceRecords.size() - 1) {
                            rootServer = rootOriginalServer;
                            Set<ResourceRecord> resultsA = getResults(new DNSNode(record.getTextResult(), RecordType.A), indirectionLevel+1);
                            if (resultsA.size() > 0) {
                                rootServer = resultsA.iterator().next().getInetResult();;
                                Set<ResourceRecord> results = getResults(node, indirectionLevel+1);
                                for (ResourceRecord resourceRecord: results) {
                                    if (resourceRecord.getInetResult() != null) {
                                        cache.addResult(new ResourceRecord(node.getHostName(),node.getType(), resourceRecord.getTTL(), resourceRecord.getInetResult()));
                                    } else {
                                        cache.addResult(new ResourceRecord(node.getHostName(),node.getType(), resourceRecord.getTTL(), resourceRecord.getTextResult()));
                                    }
                                }
//                            }
//                            break;

                            }
                        }
                    }
                }
            }
        }


//        } catch (IOException e) {
//
//        }
        rootServer = rootOriginalServer;

        return cache.getCachedResults(node);
    }

    /**
     * Retrieves DNS results from a specified DNS server. Queries are sent in iterative mode,
     * and the query is repeated with a new server if the provided one is non-authoritative.
     * Results are stored in the cache.
     *
     * @param node   Host name and record type to be used for the query.
     * @param server Address of the server to be used for the query.
     */
    private static void retrieveResultsFromServer(DNSNode node, InetAddress server) {

        // TODO To be completed by the student

        try {
            answersResourceRecords = new ArrayList<>();
            nsResourceRecords = new ArrayList<>();
            additionalResourceRecords = new ArrayList<>();

            if (verboseTracing) System.out.println();
            if (verboseTracing) System.out.println();
            Random random = new Random();
            int queryId = random.nextInt(65336);

            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(byteArrayOutputStream);

            dos.writeShort(queryId);
            dos.writeByte(0x00);
            dos.writeByte(0x00);
            dos.writeShort(0x0001);
            dos.writeShort(0x0000);
            dos.writeShort(0x0000);
            dos.writeShort(0x0000);

            String[] fqdnParts = node.getHostName().split("\\.");

            for (int i = 0; i < fqdnParts.length; i++) {
                byte[] bytes = fqdnParts[i].getBytes();
                dos.writeByte(bytes.length);
                dos.write(bytes);
            }
            dos.writeByte(0x00);
            dos.writeShort(node.getType().getCode());
            dos.writeShort(0x0001);

            dnsQuery = byteArrayOutputStream.toByteArray();


            if (verboseTracing) System.out.println("Query ID     " + queryId + " " + node.getHostName()
                    + "  " + node.getType().name() + " --> " + server.getHostAddress());

            socket = new DatagramSocket();
            socket.setSoTimeout(5000);

            DatagramPacket packet = new DatagramPacket(dnsQuery, dnsQuery.length, server, DEFAULT_DNS_PORT);
            socket.send(packet);

            byte[] receivedData = new byte[1024];
            byteNo = 0;
            try {
                DatagramPacket receivePacket = new DatagramPacket(receivedData,
                        receivedData.length);
                socket.receive(receivePacket);
            } catch (SocketTimeoutException e) {
                try {
                    DatagramPacket newPacket = new DatagramPacket(dnsQuery, dnsQuery.length, server, DEFAULT_DNS_PORT);
                    socket.setSoTimeout(5000);
                    socket.send(newPacket);
                    if (verboseTracing) System.out.println();
                    if (verboseTracing) System.out.println();
                    if (verboseTracing) System.out.println("Query ID     " + queryId + " " + node.getHostName()
                            + "  " + node.getType().name() + " --> " + server.getHostAddress());
                    DatagramPacket receivePacket = new DatagramPacket(receivedData,
                            receivedData.length);
                    socket.receive(receivePacket);
                } catch (SocketTimeoutException e1) {
                    return;
                }

            }

            //Query ID
            int queryID = (receivedData[byteNo++] << 8) & 0xff00;
            queryID = (queryID) | (receivedData[byteNo++]) & 0xff;


            //QR, Opcode, AA, TC, TD
            byte qaOpcodeAATCRD = receivedData[byteNo++];

            int qrMask = 255;
            int qr = (qaOpcodeAATCRD & qrMask) >> 7;
//            System.out.println("QR: " + qr);

            int opcodeMask = 127;
            int opcode = (qaOpcodeAATCRD & opcodeMask) >> 3;
//            System.out.println("Opcode: " + opcode);

            int aaMask = 7;
            int aa = (qaOpcodeAATCRD & aaMask) >> 2;
//            System.out.println("AA: " + opcode);

            int tcMask = 3;
            int tc = (qaOpcodeAATCRD & tcMask) >> 1;
//            System.out.println("TC: " + opcode);

            int rdMask = 1;
            int rd = qaOpcodeAATCRD & rdMask;
//            System.out.println("RD: " + opcode);


            //RA, Z, RCODE
            byte raZRCODE = receivedData[byteNo++];

            int raMask = 255;
            int ra = (raZRCODE & raMask) >> 7;
//            System.out.println("RA: " + ra);

            int zMask = 127;
            int z = (raZRCODE * zMask) >> 4;
//            System.out.println("Z: " + z);

            int rcodeMask = 15;
            int rcode = raZRCODE & rcodeMask;
            if (rcode == 3 || rcode == 5) {
                return;
            }
//            System.out.println("RCODE: " + rcode);


            //Query Count
            int qdcount = 0;
            qdcount = (receivedData[byteNo++] << 8) & 0xff00;
            qdcount = (qdcount) | (receivedData[byteNo++]) & 0xff;
//            System.out.println("QDCOUNT: " + qdcount);
            if (qdcount != 1) {
                if (verboseTracing) System.out.println("Error: Query Count not equal to 1");
                return;
            }

            //Answer Count
            int ancount = (receivedData[byteNo++] << 8) & 0xff00;
            ancount = (ancount) | (receivedData[byteNo++]) & 0xff;
//            System.out.println("ANCOUNT: " + ancount);

            //Name Server Records
            int nscount = (receivedData[byteNo++] << 8) & 0xff00;
            nscount = (nscount) | (receivedData[byteNo++]) & 0xff;
//            System.out.println("NSCOUNT: " + nscount);

            //Additional Record Count
            int arccount = (receivedData[byteNo++] << 8) & 0xff00;
            arccount = (arccount) | (receivedData[byteNo++]) & 0xff;
//            System.out.println("ARCOUNT: " + arccount);

            //QNAME
            String qName = getFQDN(receivedData, byteNo);

            //Skip QType and QClass
            byteNo = byteNo + 4;

            //Answers

            if (verboseTracing) System.out.println("Response ID: " + queryID + " Authoritative = " + (ancount > 0));

            for(int i = 0; i < ancount; i++) {
                ResourceRecord resourceRecord = parseResourceRecord(receivedData);

                if (resourceRecord != null) {
                    answersResourceRecords.add(resourceRecord);
                    cache.addResult(resourceRecord);
                }
            }

            for(int i = 0; i < nscount; i++) {
                ResourceRecord resourceRecord = parseResourceRecord(receivedData);
                if (resourceRecord != null) {
                    nsResourceRecords.add(resourceRecord);
                    cache.addResult(resourceRecord);
                }
            }

//            if (verboseTracing) System.out.println("  Additional Information (" + arccount + ")");
            for(int i = 0; i < arccount; i++) {
                ResourceRecord resourceRecord = parseResourceRecord(receivedData);
                if (resourceRecord != null) {
                    additionalResourceRecords.add(resourceRecord);
                    cache.addResult(resourceRecord);
                }
            }

            if (verboseTracing) System.out.println("  Answers (" + answersResourceRecords.size() + ")");
            for (int i = 0; i < answersResourceRecords.size(); i++) {
                verbosePrintResourceRecord(answersResourceRecords.get(i), answersResourceRecords.get(i).getType().getCode());
            }

            if (verboseTracing) System.out.println("  Nameservers (" + nsResourceRecords.size() + ")");
            for (int i = 0; i < nsResourceRecords.size(); i++) {
                verbosePrintResourceRecord(nsResourceRecords.get(i), nsResourceRecords.get(i).getType().getCode());
            }


            if (verboseTracing) System.out.println("  Additional Information (" + additionalResourceRecords.size() + ")");
            for (int i = 0; i < additionalResourceRecords.size(); i++) {
                verbosePrintResourceRecord(additionalResourceRecords.get(i), additionalResourceRecords.get(i).getType().getCode());
            }



        } catch (IOException e) {

        }
    }

    private static ResourceRecord parseResourceRecord(byte[] receivedData) {
        String fqdn = getFQDN(receivedData, byteNo);
//        System.out.println("FQDN: " + fqdn);

        int rrType = (receivedData[byteNo++] << 8) & 0xff00;
        rrType = (rrType) | ((receivedData[byteNo++]) & 0xff);
//        System.out.println("Type: " + rrType);

        int rrClass = (receivedData[byteNo++] << 8) & 0xff00;
        rrClass = (rrClass) | ((receivedData[byteNo++]) & 0xff);
//        System.out.println("Class: " + rrClass);

        int rrTTL = (receivedData[byteNo++] << 24) & 0xff000000;
        rrTTL = (rrTTL) | ((receivedData[byteNo++] << 16) & 0xff0000);
        rrTTL = (rrTTL) | ((receivedData[byteNo++] << 8) & 0xff00);
        rrTTL = (rrTTL) | ((receivedData[byteNo++]) & 0xff);
//        System.out.println("TTL: " + rrTTL);
        byteNo += 2;
        try {
            if (rrClass == 1 && rrType == 1) {
                byte[] ipaddress = new byte[4];
                for (int j = 0; j < 4; j++) {
                    ipaddress[j] = receivedData[byteNo++];
                }
                return new ResourceRecord(fqdn, RecordType.getByCode(rrType), rrTTL, InetAddress.getByAddress(ipaddress));
            } else if (rrType == 2 || rrType == 5) {
                String newFqdn = getFQDN(receivedData, byteNo);
//                System.out.println(newFqdn);
//                System.out.println(rrTTL);
//                System.out.println(RecordType.getByCode(rrType));
                return new ResourceRecord(fqdn, RecordType.getByCode(rrType), rrTTL, newFqdn);
            } else if (rrType == 28) {
                byte[] ipaddress = new byte[16];
                for (int j = 0; j < 16; j++) {
                    ipaddress[j] = receivedData[byteNo++];
                }

                return new ResourceRecord(fqdn, RecordType.getByCode(rrType), rrTTL, InetAddress.getByAddress(ipaddress));
            }
        } catch (UnknownHostException e) {
            if (verboseTracing) System.out.println("Failed to convert address.");
        }
        return null;
    }

    private static void verbosePrintResourceRecord(ResourceRecord record, int rtype) {
        if (verboseTracing)
            System.out.format("       %-30s %-10d %-4s %s\n", record.getHostName(),
                    record.getTTL(),
                    record.getType() == RecordType.OTHER ? rtype : record.getType(),
                    record.getTextResult());
    }

    /**
     * Prints the result of a DNS query.
     *
     * @param node    Host name and record type used for the query.
     * @param results Set of results to be printed for the node.
     */
    private static void printResults(DNSNode node, Set<ResourceRecord> results) {
        if (results.isEmpty())
            System.out.printf("%-30s %-5s %-8d %s\n", node.getHostName(),
                    node.getType(), -1, "0.0.0.0");
        for (ResourceRecord record : results) {
            System.out.printf("%-30s %-5s %-8d %s\n", node.getHostName(),
                    node.getType(), record.getTTL(), record.getTextResult());
        }
    }

    private static String getFQDN(byte[] receivedData, int byteNoCopy) {
        StringBuilder fqdn = new StringBuilder();
        boolean firstTime = true;
        boolean compressed = false;
        for (int cnt = receivedData[byteNoCopy]; cnt != 0; ) {
            if (!firstTime) {
                fqdn.append(".");
            } else {
                firstTime = false;
            }

            if((receivedData[byteNoCopy] & 0xC0) > 0) {
                compressed = true;
                int offset = (cnt & 0x3f) << 8;
                offset = (receivedData[++byteNoCopy] & 0xff);
                byteNoCopy = offset;
                cnt = receivedData[byteNoCopy];
                firstTime = true;
            } else {
                for (int i = 1; i <= cnt; i++) {
                    fqdn.append((char) receivedData[byteNoCopy + i]);
                }

                if(!compressed) {
                    byteNo += (cnt + 1);
                }

                byteNoCopy += (cnt + 1);
                cnt = receivedData[byteNoCopy];
            }
        }

        if(compressed) {
            byteNo += 2;
        } else {
            byteNo += 1;
        }

        return fqdn.toString();
    }
}