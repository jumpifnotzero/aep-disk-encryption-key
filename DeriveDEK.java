import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * Example code illustrating derivation of the disk encryption key
 */
public class DeriveDEK {

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("pass pin as a parameter");
            System.exit(1);
        }
        String pin = args[0];

        // derive passwords
        final byte[] password1 = getPassword(pin.getBytes(), 0x36);
        final byte[] password2 = getPassword(pin.getBytes(), 0x5C);

        // derive salt
        final byte[] salt = getSalt(pin.getBytes());

        // the following code is effectively a pbkdf2 implementation for the token store
        // it chains two iterations of sha1 using two separate passwords for each iteration
        // 3des is a 168-bit key (21 bytes) and one iteration is 20 bytes, so we truncate 2 iterations.
        ByteArrayOutputStream bos = new ByteArrayOutputStream(40);
        bos.write(f(password1, password2, salt, 10,0x1));
        bos.write(f(password1, password2, salt, 10,0x2));
        final byte[] output = Arrays.copyOf(bos.toByteArray(), 0x15);

        // we have a key without parity bits set
        // the parity bit is the least significant byte, i.e. 0x1 bit.
        final byte[] k = setParity(expand(output));
        System.out.println(bytesToHex(k));
    }

    private static byte[] getSalt(final byte[] pin) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        bos.write(new byte[] {0x55,0x55,0x55,0x55});
        bos.write(new byte[] {0x55,0x55,0x55,0x55});
        bos.write(new byte[] {(byte) 0xaa,(byte) 0xaa,(byte) 0xaa,(byte) 0xaa,});
        bos.write(new byte[] {(byte) 0xaa,(byte) 0xaa,(byte) 0xaa,(byte) 0xaa,});
        bos.write(pin);
        bos.write(new byte[] {0x55,0x55,0x55,0x55});
        bos.write(new byte[] {0x55,0x55,0x55,0x55});
        bos.write(new byte[] {(byte) 0xaa,(byte) 0xaa,(byte) 0xaa,(byte) 0xaa,});
        bos.write(new byte[] {(byte) 0xaa,(byte) 0xaa,(byte) 0xaa,(byte) 0xaa,});

        MessageDigest md = MessageDigest.getInstance("SHA1");
        md.update(bos.toByteArray());
        return md.digest();
    }

    private static byte[] getPassword(final byte[] pin, int mask) {
        byte[] result = Arrays.copyOf(pin, 0x40);
        for (int j = 0; j < result.length; j++) {
            result[j] = (byte) (result[j] ^ mask);
        }
        return result;
    }

    private static byte[] f(final byte[] password1, final byte[] password2, final byte[] salt, final int iterations, final int i) throws Exception {
        byte[] output = new byte[] {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

        MessageDigest md = MessageDigest.getInstance("SHA1");
        byte[] interim = salt;
        for (int j = 0; j < iterations; j++) {

            // generate the first round
            md.update(password1);
            md.update(interim);
            if (j == 0) {
                md.update(new byte[]{0, 0, 0, (byte) i});
            }
            interim = md.digest();

            // generate the second round
            md.update(password2);
            md.update(interim);
            interim = md.digest();

            // xor of this iteration
            for (int k = 0; k < output.length; k++) {
                output[k] = (byte) (output[k] ^ interim[k]);
            }

        }
        return output;
    }

    /*
     * Expand the 168-bit key to 192-bit to hold parity bits.
     */
    private static byte[] expand(final byte[] key) {
        byte[] k = new byte[24]; // 192 bit
        k[0] = (byte) ((key[0] & 0b11111110) & 0xFF);
        k[1] = (byte) ((((key[0] & 0b00000001) << 7) | ((key[1] & 0b11111100)) >> 1) & 0xFF);
        k[2] = (byte) ((((key[1] & 0b00000011) << 6) | ((key[2] & 0b11111000)) >> 2) & 0xFF);
        k[3] = (byte) ((((key[2] & 0b00000111) << 5) | ((key[3] & 0b11110000)) >> 3) & 0xFF);
        k[4] = (byte) ((((key[3] & 0b00001111) << 4) | ((key[4] & 0b11100000)) >> 4) & 0xFF);
        k[5] = (byte) ((((key[4] & 0b00011111) << 3) | ((key[5] & 0b11000000)) >> 5) & 0xFF);
        k[6] = (byte) ((((key[5] & 0b00111111) << 2) | ((key[6] & 0b10000000)) >> 6) & 0xFF);
        k[7] = (byte) (((key[6] & 0b01111111) << 1) & 0xFF);


        k[ 8] = (byte) ((key[7] & 0b11111110) & 0xFF);
        k[ 9] = (byte) ((((key[7] & 0b00000001) << 7) | ((key[8] & 0b11111100)) >> 1) & 0xFF);
        k[10] = (byte) ((((key[8] & 0b00000011) << 6) | ((key[9] & 0b11111000)) >> 2) & 0xFF);
        k[11] = (byte) ((((key[9] & 0b00000111) << 5) | ((key[10] & 0b11110000)) >> 3) & 0xFF);
        k[12] = (byte) ((((key[10] & 0b00001111) << 4) | ((key[11] & 0b11100000)) >> 4) & 0xFF);
        k[13] = (byte) ((((key[11] & 0b00011111) << 3) | ((key[12] & 0b11000000)) >> 5) & 0xFF);
        k[14] = (byte) ((((key[12] & 0b00111111) << 2) | ((key[13] & 0b10000000)) >> 6) & 0xFF);
        k[15] = (byte) (((key[13] & 0b01111111) << 1) & 0xFF);

        k[16] = (byte) ((key[14] & 0b11111110) & 0xFF);
        k[17] = (byte) ((((key[14] & 0b00000001) << 7) | ((key[15] & 0b11111100)) >> 1) & 0xFF);
        k[18] = (byte) ((((key[15] & 0b00000011) << 6) | ((key[16] & 0b11111000)) >> 2) & 0xFF);
        k[19] = (byte) ((((key[16] & 0b00000111) << 5) | ((key[17] & 0b11110000)) >> 3) & 0xFF);
        k[20] = (byte) ((((key[17] & 0b00001111) << 4) | ((key[18] & 0b11100000)) >> 4) & 0xFF);
        k[21] = (byte) ((((key[18] & 0b00011111) << 3) | ((key[19] & 0b11000000)) >> 5) & 0xFF);
        k[22] = (byte) ((((key[19] & 0b00111111) << 2) | ((key[20] & 0b10000000)) >> 6) & 0xFF);
        k[23] = (byte) (((key[20] & 0b01111111) << 1) & 0xFF);
        return k;
    }

    // calcualte the parity bit for each byte
    private static byte[] setParity(final byte[] key) {
        byte[] result = Arrays.copyOf(key, key.length);
        for (int z = 0; z < result.length; z++) {
            result[z] = (byte) (result[z] | parity(result[z]));
        }
        return result;
    }

    // returns either 0 or 1 to give odd parity
    private static byte parity(byte b) {
        int parity = 1;
        parity ^= (b & 0x1);
        parity ^= ((b >> 1) & 0x1);
        parity ^= ((b >> 2) & 0x1);
        parity ^= ((b >> 3) & 0x1);
        parity ^= ((b >> 4) & 0x1);
        parity ^= ((b >> 5) & 0x1);
        parity ^= ((b >> 6) & 0x1);
        parity ^= ((b >> 7) & 0x1);
        return (byte) parity;
    }

    // from https://stackoverflow.com/questions/9655181/how-to-convert-a-byte-array-to-a-hex-string-in-java#9855338
    private final static char[] hexArray = "0123456789ABCDEF".toCharArray();
    private static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

}
