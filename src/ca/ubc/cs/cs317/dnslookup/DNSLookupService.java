package ca.ubc.cs.cs317.dnslookup;

import java.io.IOException;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.SecureRandom;
import java.util.*;
import java.util.stream.IntStream;

public class DNSLookupService {

    private static final int DEFAULT_DNS_PORT = 53;
    private static final int MAX_INDIRECTION_LEVEL_NS = 10;
    private static final int MAX_QUERY_ATTEMPTS = 3;
    protected static final int SO_TIMEOUT = 5000;

    private final DNSCache cache = DNSCache.getInstance();
    private final Random random = new SecureRandom();
    private final DNSVerbosePrinter verbose;
    private final DatagramSocket socket;
    private InetAddress nameServer;

    private static int pointer = 0;

    /**
     * Creates a new lookup service. Also initializes the datagram socket object with a default timeout.
     *
     * @param nameServer The nameserver to be used initially. If set to null, "root" or "random", will choose a random
     *                   pre-determined root nameserver.
     * @param verbose    A DNSVerbosePrinter listener object with methods to be called at key events in the query
     *                   processing.
     * @throws SocketException      If a DatagramSocket cannot be created.
     * @throws UnknownHostException If the nameserver is not a valid server.
     */
    public DNSLookupService(String nameServer, DNSVerbosePrinter verbose) throws SocketException, UnknownHostException {
        this.verbose = verbose;
        socket = new DatagramSocket();
        socket.setSoTimeout(SO_TIMEOUT);
        this.setNameServer(nameServer);
    }

    /**
     * Returns the nameserver currently being used for queries.
     *
     * @return The string representation of the nameserver IP address.
     */
    public String getNameServer() {
        return this.nameServer.getHostAddress();
    }

    /**
     * Updates the nameserver to be used in all future queries.
     *
     * @param nameServer The nameserver to be used initially. If set to null, "root" or "random", will choose a random
     *                   pre-determined root nameserver.
     * @throws UnknownHostException If the nameserver is not a valid server.
     */
    public void setNameServer(String nameServer) throws UnknownHostException {

        // If none provided, choose a random root nameserver
        if (nameServer == null || nameServer.equalsIgnoreCase("random") || nameServer.equalsIgnoreCase("root")) {
            List<ResourceRecord> rootNameServers = cache.getCachedResults(cache.rootQuestion, false);
            nameServer = rootNameServers.get(0).getTextResult();
        }
        this.nameServer = InetAddress.getByName(nameServer);
    }

    /**
     * Closes the lookup service and related sockets and resources.
     */
    public void close() {
        socket.close();
    }

    /**
     * Finds all the result for a specific node. If there are valid (not expired) results in the cache, uses these
     * results, otherwise queries the nameserver for new records. If there are CNAME records associated to the question,
     * they are included in the results as CNAME records (i.e., not queried further).
     *
     * @param question Host and record type to be used for search.
     * @return A (possibly empty) set of resource records corresponding to the specific query requested.
     */
    public Collection<ResourceRecord> getDirectResults(DNSQuestion question) {

        Collection<ResourceRecord> results = cache.getCachedResults(question, true);
        if (results.isEmpty()) {
            iterativeQuery(question, nameServer);
            results = cache.getCachedResults(question, true);
        }
        return results;
    }

    /**
     * Finds all the result for a specific node. If there are valid (not expired) results in the cache, uses these
     * results, otherwise queries the nameserver for new records. If there are CNAME records associated to the question,
     * they are retrieved recursively for new records of the same type, and the returning set will contain both the
     * CNAME record and the resulting addresses.
     *
     * @param question             Host and record type to be used for search.
     * @param maxIndirectionLevels Number of CNAME indirection levels to support.
     * @return A set of resource records corresponding to the specific query requested.
     * @throws CnameIndirectionLimitException If the number CNAME redirection levels exceeds the value set in
     *                                        maxIndirectionLevels.
     */
    public Collection<ResourceRecord> getRecursiveResults(DNSQuestion question, int maxIndirectionLevels)
            throws CnameIndirectionLimitException {

        if (maxIndirectionLevels < 0) throw new CnameIndirectionLimitException();

        Collection<ResourceRecord> directResults = getDirectResults(question);
        if (directResults.isEmpty() || question.getRecordType() == RecordType.CNAME)
            return directResults;

        List<ResourceRecord> newResults = new ArrayList<>();
        for (ResourceRecord record : directResults) {
            newResults.add(record);
            if (record.getRecordType() == RecordType.CNAME) {
                newResults.addAll(getRecursiveResults(
                        new DNSQuestion(record.getTextResult(), question.getRecordType(), question.getRecordClass()),
                        maxIndirectionLevels - 1));
            }
        }
        return newResults;
    }

    /**
     * Retrieves DNS results from a specified DNS server using the iterative mode. After an individual query is sent and
     * its response is received (or times out), checks if an answer for the specified host exists. Resulting values
     * (including answers, nameservers and additional information provided by the nameserver) are added to the cache.
     * <p>
     * If after the first query an answer exists to the original question (either with the same record type or an
     * equivalent CNAME record), the function returns with no further actions. If there is no answer after the first
     * query but the response returns at least one nameserver, a follow-up query for the same question must be done to
     * another nameserver. Note that nameservers returned by the response contain text records linking to the host names
     * of these servers. If at least one nameserver provided by the response to the first query has a known IP address
     * (either from this query or from a previous query), it must be used first, otherwise additional queries are
     * required to obtain the IP address of the nameserver before it is queried. Only one nameserver must be contacted
     * for the follow-up query.
     *
     * @param question Host name and record type/class to be used for the query.
     * @param server   Address of the server to be used for the first query.
     */
    protected void iterativeQuery(DNSQuestion question, InetAddress server) {

        /* TO BE COMPLETED BY THE STUDENT */
        Set<ResourceRecord> nextNameServers;
        InetAddress IP = null;
        DNSQuestion nameServerQuestion = null;
        nextNameServers = individualQueryProcess(question, server);

        while (!nextNameServers.isEmpty() && cache.getCachedResults(question, true).isEmpty()) {
            for (ResourceRecord record : nextNameServers) {
                nameServerQuestion = new DNSQuestion(record.getTextResult(),
                        RecordType.A, record.getRecordClass());
                List<ResourceRecord> nextNS = cache.getCachedResults(nameServerQuestion, true);
                if (nextNS.isEmpty()) {
                    continue;
                } else {
                    try {
                        IP = nextNS.get(0).getInetResult();
                        break;
                    } catch (Exception e) {
                        // Do nothing
                    }
                }
            }
            if (IP != null) {
                iterativeQuery(question, IP);
            } else {
                iterativeQuery(nameServerQuestion, nameServer);
            }
        }
    }

    /**
     * Handles the process of sending an individual DNS query to a single question. Builds and sends the query (request)
     * message, then receives and parses the response. Received responses that do not match the requested transaction ID
     * are ignored. If no response is received after SO_TIMEOUT milliseconds, the request is sent again, with the same
     * transaction ID. The query should be sent at most MAX_QUERY_ATTEMPTS times, after which the function should return
     * without changing any values. If a response is received, all of its records are added to the cache.
     * <p>
     * The method verbose.printQueryToSend() must be called every time a new query message is about to be sent.
     *
     * @param question Host name and record type/class to be used for the query.
     * @param server   Address of the server to be used for the query.
     * @return If no response is received, returns null. Otherwise, returns a set of resource records for all
     * nameservers received in the response. Only records found in the nameserver section of the response are included,
     * and only those whose record type is NS. If a response is received but there are no nameservers, returns an empty
     * set.
     */
    protected Set<ResourceRecord> individualQueryProcess(DNSQuestion question, InetAddress server) {
        // First pass implementation for testing other functions
        // TODO: Refine once called functions are implemented
        int TEMP_BUFF_SIZE = 1024;
        ByteBuffer queryBuffer = ByteBuffer.allocate(TEMP_BUFF_SIZE);
        ByteBuffer responseBuffer = ByteBuffer.allocate(TEMP_BUFF_SIZE);
        int transactionID = buildQuery(queryBuffer, question);
        int receivedTransactionID = 999999; // set as Invalid ID

        int queryAttempt = 0;
        while (queryAttempt < MAX_QUERY_ATTEMPTS) {
            try {
                verbose.printQueryToSend(question, server, transactionID);
                socket.send(new DatagramPacket(queryBuffer.array(), queryBuffer.position(), server, DEFAULT_DNS_PORT));
                DatagramPacket responsePacket = new DatagramPacket(responseBuffer.array(), TEMP_BUFF_SIZE);
                queryAttempt++;
                long timeOut = System.currentTimeMillis() + SO_TIMEOUT;

                while (transactionID != receivedTransactionID && System.currentTimeMillis() < timeOut) {
                    try {
                        socket.receive(responsePacket);
                        receivedTransactionID = responseBuffer.getShort(0);
                    } catch (IOException e) {}
                }
                boolean isResponse = ((responseBuffer.get(2) >> 7) & 0x01) == 1; //QR is 1 meaning response
                if (transactionID == receivedTransactionID && isResponse) { // if ID matches and is a response
                    Set<ResourceRecord> nameServerResults = processResponse(responseBuffer);
                    return nameServerResults;
                }
                return null;
            } catch (IOException e) {}
        }

        return null; // return null if no response received
    }

    /**
     * Fills a ByteBuffer object with the contents of a DNS query. The buffer must be updated from the start (position
     * 0). A random transaction ID must also be generated and filled in the corresponding part of the query. The query
     * must be built as an iterative (non-recursive) request for a regular query with a single question. When the
     * function returns, the buffer's position (`queryBuffer.position()`) must be equivalent to the size of the query
     * data.
     *
     * @param queryBuffer The ByteBuffer object where the query will be saved.
     * @param question    Host name and record type/class to be used for the query.
     * @return The transaction ID used for the query.
     */
    protected int buildQuery(ByteBuffer queryBuffer, DNSQuestion question) {
        byte[] transactionID = new byte[2];
        random.nextBytes(transactionID);
        queryBuffer.put(transactionID);

        // Basic DNS header for a single, non recursive question
        byte[] header = {   // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                0x00, 0x00, // |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
                0x00, 0x01, // |                    QDCOUNT                    |
                0x00, 0x00, // |                    ANCOUNT                    |
                0x00, 0x00, // |                    NSCOUNT                    |
                0x00, 0x00  // |                    ARCOUNT                    |
        };
        queryBuffer.put(header);

        // Place host name in buffer following rfc1035 specs
        String[] hostName = question.getHostName().split("\\.");
        for (String label : hostName) {
            queryBuffer.put((byte) label.length());
            for (byte charByte : label.getBytes()) {
                queryBuffer.put(charByte);
            }
        }
        // Host name terminator
        queryBuffer.put((byte) 0x00);

        queryBuffer.putShort((short) question.getRecordType().getCode());
        queryBuffer.putShort((short) question.getRecordClass().getCode());

        return ByteBuffer.wrap(transactionID).getShort();
    }

    /**
     * Parses and processes a response received by a nameserver. Adds all resource records found in the response message
     * to the cache. Calls methods in the verbose object at appropriate points of the processing sequence. Must be able
     * to properly parse records of the types: A, AAAA, NS, CNAME and MX (the priority field for MX may be ignored). Any
     * other unsupported record type must create a record object with the data represented as a hex string (see method
     * byteArrayToHexString).
     *
     * @param responseBuffer The ByteBuffer associated to the response received from the server.
     * @return A set of resource records for all nameservers received in the response. Only records found in the
     * nameserver section of the response are included, and only those whose record type is NS. If there are no
     * nameservers, returns an empty set.
     */
    protected Set<ResourceRecord> processResponse(ByteBuffer responseBuffer) {

        // Process Response Header
        int ID = responseBuffer.getShort(0);
        boolean AA = ((responseBuffer.get(2) >> 2) & 0x01) == 1;
        int RCODE = responseBuffer.get(3) & 0x0F;

        verbose.printResponseHeaderInfo(ID, AA, RCODE);

        // Count of Questions, Answers, NameServers & Additional Records
        int QDCOUNT = responseBuffer.getShort(4);
        int ANCOUNT = responseBuffer.getShort(6);
        int NSCOUNT = responseBuffer.getShort(8);
        int ARCOUNT = responseBuffer.getShort(10);

        // Skip over the question section
        pointer = 12; // Start of QNAME in first Question section
        for (int i = 0; i < QDCOUNT; i++) {
            while (responseBuffer.get(pointer) != 0) {
                pointer++;
            }
            pointer += 5;
        }

        // Process Resource Records
        Set<ResourceRecord> answerRecords = new HashSet<>();
        Set<ResourceRecord> authorityRecords = new HashSet<>();
        Set<ResourceRecord> additionalRecords = new HashSet<>();

        try {
            verbose.printAnswersHeader(ANCOUNT);
            for (int i = 0; i < ANCOUNT; i++) {
                processRecords(responseBuffer, answerRecords);
            }
            verbose.printNameserversHeader(NSCOUNT);
            for (int i = 0; i < NSCOUNT; i++) {
                processRecords(responseBuffer, authorityRecords);
            }
            verbose.printAdditionalInfoHeader(ARCOUNT);
            for (int i = 0; i < ARCOUNT; i++) {
                processRecords(responseBuffer, additionalRecords);
            }
        } catch (Exception e) {
            // Do nothing
        }

        // Filter out NS records
        Set<ResourceRecord> nsRecords = new HashSet<>();
        for (ResourceRecord record : authorityRecords) {
            if (record.getRecordType() == RecordType.NS) {
                nsRecords.add(record);
            }
        }

        return nsRecords;
    }

    /**
     * Helper function that converts a hex string representation of a byte array. May be used to represent the result of
     * records that are returned by the nameserver but not supported by the application (e.g., SOA records).
     *
     * @param data a byte array containing the record data.
     * @return A string containing the hex value of every byte in the data.
     */
    private static String byteArrayToHexString(byte[] data) {
        return IntStream.range(0, data.length).mapToObj(i -> String.format("%02x", data[i])).reduce("", String::concat);
    }

    public static class CnameIndirectionLimitException extends Exception {
    }

    /**
     * Helper function to process resource records.
     */
    private void processRecords(ByteBuffer responseBuffer, Set<ResourceRecord> records) {
        //System.out.println(String.format("0x%08X", responseBuffer.get(pointer)));
        // Get Hostname
        String hostName = getName(responseBuffer, pointer);
        // Get Type
        int typeCode = responseBuffer.getShort(pointer);
        RecordType type = RecordType.getByCode(typeCode);
        pointer += 2;
        // Get Class
        int classCode = responseBuffer.getShort(pointer);
        RecordClass recordClass = RecordClass.getByCode(classCode);
        pointer += 2;
        // Get TTL
        int ttl = responseBuffer.getInt(pointer);
        pointer += 4;
        // Get RDLENGTH
        int rdLength = responseBuffer.getShort(pointer);
        pointer += 2;

        // Get RDATA
        String result = "";
        if (type == RecordType.A) {
            result = String.format("%d.%d.%d.%d", responseBuffer.get(pointer) & 0xFFL,
                    responseBuffer.get(pointer + 1) & 0xFFL, responseBuffer.get(pointer + 2)& 0xFFL,
                    responseBuffer.get(pointer + 3) & 0xFFL); // OxFFL for unsigned byte
            pointer += 4;
        } else if (type == RecordType.AAAA) {
            result = String.format("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                    responseBuffer.get(pointer), responseBuffer.get(pointer + 1), responseBuffer.get(pointer + 2),
                    responseBuffer.get(pointer + 3), responseBuffer.get(pointer + 4), responseBuffer.get(pointer + 5),
                    responseBuffer.get(pointer + 6), responseBuffer.get(pointer + 7), responseBuffer.get(pointer + 8),
                    responseBuffer.get(pointer + 9), responseBuffer.get(pointer + 10), responseBuffer.get(pointer + 11),
                    responseBuffer.get(pointer + 12), responseBuffer.get(pointer + 13), responseBuffer.get(pointer + 14),
                    responseBuffer.get(pointer + 15));
            pointer += 16;
        } else if (type == RecordType.CNAME || type == RecordType.NS || type == RecordType.MX) {
            if (type == RecordType.MX) {
                pointer += 2; // Skip preference
            }
            result = getName(responseBuffer, pointer);
        } else {
            byte data[] = new byte[rdLength];
            for (int i = 0; i < rdLength; i++) {
                data[i] = responseBuffer.get(pointer);
                pointer++;
            }
            result = byteArrayToHexString(data);
        }

        InetAddress IP = null;
        try {
            IP = InetAddress.getByName(result);
        } catch (Exception e) {
            // Do nothing
        }

        DNSQuestion question = new DNSQuestion(hostName, type, recordClass);

        ResourceRecord resourceRecord;
        if (IP != null && (type == RecordType.A || type == RecordType.AAAA)) {
            resourceRecord = new ResourceRecord(question, ttl, IP);
        } else {
            resourceRecord = new ResourceRecord(question, ttl, result);
        }

        verbose.printIndividualResourceRecord(resourceRecord, typeCode, classCode);
        records.add(resourceRecord);
        cache.addResult(resourceRecord);
    }

    /**
     * Helper function to decode a domain name.
     */
    private static String getName(ByteBuffer responseBuffer, int ptr) {
        String name = "";

        while(true) {
            int labelLength = responseBuffer.get(ptr);
            // 0 indicates end of name
            if (labelLength== 0)
                break;
            // 0xC0 indicates a pointer to the next byte
            else if (responseBuffer.get(ptr) == (byte) 0xc0) {
                int newPtr = ((responseBuffer.get(ptr) & 0x3F) << 8) | (responseBuffer.get(ptr + 1) & 0xFF);
                ptr++;
                // Recursively call getNameFromPointer to get the name
                name += getName(responseBuffer, newPtr);
                break;
            }
            // Reading a normal label
            else {
                for (int i = 0; i < labelLength; i++) {
                    ptr++;
                    char ch = (char) (responseBuffer.get(ptr));
                    name += ch;
                }
                name += '.';
                ptr++;
            }
        }

        pointer = ptr + 1;

        // Remove trailing '.'
        if (name.length() > 0 && name.charAt(name.length() - 1) == '.') {
            name = name.substring(0, name.length() - 1);
        }

        return name;
    }
}
