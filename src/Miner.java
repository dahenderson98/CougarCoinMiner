import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Scanner;

public class Miner {

    public ArrayList<String> blockHeaderHashes;
    public static final String P2PKH = "20954b556d7922ed936c05252e8494e7c401a9a995a1c9468f3dcdf8a4b15fe7"; // Hash of "Dallin Henderson"
    public static final String TARGET_VALUE = "000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    public static final String GEN_BLOCK_FILE_NAME = "genesis.txt";
    public static final String OUTPUT_FILE_NAME = "output.txt";
    public static final int NUM_BLOCKS = 10;
    public static final int TARGET_LEADING_ZEROES = 6;
    public static final int MAX_NONCE_TESTS = Integer.MAX_VALUE;

    public Miner(){
        this.blockHeaderHashes = new ArrayList<>();
    }

    public static void main(String[] args) {
        String genesisHeader = "header:\n" +
                "timestamp: 2022-02-03 16:15:00\n" +
                "prev: 0x0000000000000000000000000000000000000000000000000000000000000000\n" +
                "root: 0x96837d59c20b2893f5e2a9a625d2e23a5332ad7372071e267492425f171b2374\n" +
                "target: 0x" + TARGET_VALUE + "\n" +
                "nonce: 65281174\n\n";

        // Read in genesis block text from genesis.txt
        String genesisText = "";
        try {
            File myObj = new File(GEN_BLOCK_FILE_NAME);
            Scanner myReader = new Scanner(myObj);
            while (myReader.hasNextLine()) {
                String data = myReader.nextLine();
                genesisText += data + '\n';
            }
            myReader.close();
        } catch (FileNotFoundException e) {
            System.out.println("File " + GEN_BLOCK_FILE_NAME + " not found");
            e.printStackTrace();
        }

        // Write genesis block text to output.txt
        Miner miner = new Miner();
        try {
            miner.writeToFile(genesisText, false);
        }catch (IOException e){
            System.out.println("Failed to write genesis block to header");
        }

        // Add genesis block header hash to blockHeaderHashes for next block to access
        miner.blockHeaderHashes.add(miner.sha256(genesisHeader));

        // Mine NUM_BLOCKS new blocks and write their text to output.txt
        int count = 0;
        while (count < NUM_BLOCKS){
            miner.mineBlock();
            count++;
        }
    }

    public void mineBlock() {
        // BUild transaction string
        String transaction = "transaction:\n" + "inputs:\n" + "txid:\n" + "index:\n" + "unlock:\n" + "outputs:\n" + "amount: 1000\n";
        transaction += "lock: OP_DUP OP_HASH160 <" + P2PKH + "> OP_EQUALVERIFY OP_CHECKSIG\n\n";

        // Build merkle tree from transaction above
        String merkle = "merkle:\n";
        String[] txArray = new String[1];
        txArray[0] = transaction;
        MerkleTree merkleTree = new MerkleTree(txArray);
        String[] txHashes = merkleTree.getTxDoubleHashes();
        for(String hash : txHashes){
            merkle += "0x" + hash + '\n';
        }
        if(txHashes.length % 2 != 0){
            merkle += "0x" + txHashes[txHashes.length-1] + '\n';
        }
        merkle += '\n';

        // Build block header
        final SimpleDateFormat sdf3 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        Timestamp timestamp = new Timestamp(System.currentTimeMillis());
        String header = "header:\n" + "timestamp: " + sdf3.format(timestamp) + "\nprev: 0x" + blockHeaderHashes.get(blockHeaderHashes.size() - 1) + "\n";

        // Add root, target value and calculated PoW nonce to header
        header += "root: 0x" + merkleTree.getRoot() + "\n";
        header += "target: 0x" + TARGET_VALUE + '\n';
        header += "nonce: ";
        String headerWNonce = findNonce(header);

        Block newBlock = new Block(headerWNonce,merkle,transaction);
        System.out.print(newBlock);
        try {
            writeToFile(newBlock.toString(),true);
        }catch(IOException e){
            System.out.println(e.getMessage());
        }

        // Add current header hash to blockHeaderHashes for next block to use as prev
        blockHeaderHashes.add(sha256(headerWNonce));
    }

    public String sha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] encodedhash = digest.digest(
                    input.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(encodedhash);
        }catch (NoSuchAlgorithmException e){
            return "Error:" + e.getMessage();
        }
    }

    public String doubleSha256(String input){
        return sha256(sha256(input));
    }

    private static String bytesToHex(byte[] hash) {
        StringBuilder hexString = new StringBuilder(2 * hash.length);
        for(int i = 0; i < hash.length; i++) {
            String hex = Integer.toHexString(0xff & hash[i]);
            if(hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    public String findNonce(String headerStr){
        if (headerStr.length() == 0){
            return headerStr + "Error: Empty header string" + "\n\n";
        }
        int nonce = 0;
        while (nonce < MAX_NONCE_TESTS){
            String headerHash = sha256(headerStr + nonce + "\n\n");
            int charIt = 0;
            boolean NonceBelowTargetFound = true;
            while (charIt < TARGET_LEADING_ZEROES) {
                if (headerHash.charAt(charIt) != '0') {
                    NonceBelowTargetFound = false;
                    break;
                }
                charIt++;
            }
            if (NonceBelowTargetFound){
                return headerStr + nonce + "\n\n";
            }
            nonce++;
        }
        return headerStr + "No nonce found" + "\n\n";
    }

    public void writeToFile(String data, boolean append) throws IOException {
        if (append) {
            BufferedWriter writer = new BufferedWriter(new FileWriter(OUTPUT_FILE_NAME, true));
            writer.append(data);
            writer.close();
        } else {
            BufferedWriter writer = new BufferedWriter(new FileWriter(OUTPUT_FILE_NAME));
            writer.write(data);
            writer.close();
        }
    }

    class Block{
        String header;
        String merkle;
        String transaction;

        public Block(String header, String merkle, String transaction){
            this.header = header;
            this.merkle = merkle;
            this.transaction = transaction;
        }

        @Override
        public String toString() {
            return "Block:\n" + header + merkle + transaction;
        }
    }

    class MerkleTree {
        String root;
        String[] txDoubleHashes;

        public MerkleTree(String[] transactions){
            // Double-hash all transactions and store the hashes
            ArrayList<String> doubleHashesList = new ArrayList<>();
            for (String tx : transactions){
                doubleHashesList.add(doubleSha256(tx));
            }
            txDoubleHashes = doubleHashesList.toArray(new String[0]);

            // Recursively hash roots to produce root hash
            root = getRootHash(txDoubleHashes);
        }

        public String getRootHash(String[] hashes){
            // If hash array's size is 1, return its element as the root
            if(hashes.length == 1){
                return hashes[0];
            }
            // Else, concatenate each hash pair, hash all concatenations, and recursively call getRootHash on the resulting hashes
            ArrayList<String> parentHashesList = new ArrayList<>();
            boolean oddHashCount = hashes.length % 2 != 0;
            for(int i = 0; i < hashes.length; i += 2){
                String leftHash = doubleSha256(hashes[i]);
                String rightHash;
                if(oddHashCount && (i + 2 >= hashes.length)){
                    rightHash = leftHash;
                }
                else{
                    rightHash = doubleSha256(hashes[i+1]);
                }
                parentHashesList.add(sha256(leftHash + rightHash));
            }
            return getRootHash(parentHashesList.toArray(new String[0]));
        }

        public String[] getTxDoubleHashes(){
            return txDoubleHashes;
        }

        public String getRoot(){
            return root;
        }
    }
}
