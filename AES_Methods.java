package S_AES1;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;


public class AES_Methods {
    // S-盒和逆S-盒
    public static final int[][] SBOX = {
            {0x9, 0x4, 0xA, 0xB},
            {0xD, 0x1, 0x8, 0x5},
            {0x6, 0x2, 0x0, 0x3},
            {0xC, 0xE, 0xF, 0x7}
    };

    public static final int[][] INV_SBOX = {
            {0xA, 0x5, 0x9, 0xB},
            {0x1, 0x7, 0x8, 0xF},
            {0x6, 0x0, 0x2, 0x3},
            {0xC, 0x4, 0xD, 0xE}
    };

    // 列混淆和逆列混淆矩阵
    public static final int[][] MIX_COLUMN_MATRIX = {
            {0x1, 0x4},
            {0x4, 0x1}
    };

    public static final int[][] INV_MIX_COLUMN_MATRIX = {
            {0x9, 0x2},
            {0x2, 0x9}
    };

    // 定义 RCON 常量
    public static final int[] RCON = {0b10000000, 0b00110000}; // RCON[0] = 0x80, RCON[1] = 0x30
    public static final int[][] rCON = {{0x8, 0x0}, {0x3, 0x0}};


    // 加密函数
    public static int[][] encrypt(int[][] state, int[][]Keys) {
        int[][][] roundKeys = keyExpansion(Keys);
        // 第一步：明文与密钥w0，w1进行轮密钥加
        state = addRoundKey(state, roundKeys[0]);

        // 第二步：字节替代，行移位，列混淆
        state = subNibbles(state, SBOX);

        state = shiftRows(state);

        state = mixColumns(state, MIX_COLUMN_MATRIX);

        // 第三步：扩展密钥w2，w3进行轮密钥加
        state = addRoundKey(state, roundKeys[1]);

        // 第四步：字节替代，行移位（无列混淆）
        state = subNibbles(state, SBOX);

        state = shiftRows(state);

        // 第五步：扩展密钥w4，w5进行最后一轮轮密钥加
        state = addRoundKey(state, roundKeys[2]);

        return state;
    }

    // 解密函数
    public static int[][] decrypt(int[][] state, int[][] Keys) {
        int[][][] roundKeys = keyExpansion(Keys);

        // 第一步：使用扩展密钥w4，w5进行轮密钥加
        state = addRoundKey(state, roundKeys[2]);
        // 第二步：逆行移位，逆字节替代
        state = shiftRows(state);
        state = subNibbles(state, INV_SBOX);

        // 第三步：扩展密钥w2，w3进行轮密钥加
        state = addRoundKey(state, roundKeys[1]);

        // 第四步：逆列混淆
        state = mixColumns(state, INV_MIX_COLUMN_MATRIX);

        // 第五步：逆行移位，逆字节替代
        state = shiftRows(state);
        state = subNibbles(state, INV_SBOX);

        // 第六步：初始密钥w0，w1进行最后一轮轮密钥加
        state = addRoundKey(state, roundKeys[0]);

        return state;
    }



    // 字节替代函数
    public static int[][] subNibbles(int[][] state, int[][] sbox) {

        int[][] result = new int[2][2];
        for (int i = 0; i < 2; i++) {
            for (int j = 0; j < 2; j++) {
                result[i][j] = sbox[(state[i][j] >> 2) & 0x03][state[i][j] & 0x03];
            }
        }

        return result;
    }

    // 行移位函数
    public static int[][] shiftRows(int[][] state) {
        // 第二行右移 1 位
        int temp = state[1][0];
        state[1][0] = state[1][1];
        state[1][1] = temp;
        return state;
    }




    // 列混淆函数1
    public static int[][] mixColumns(int[][] state, int[][] matrix) {
        int[][] result = new int[2][2];

        for (int i = 0; i < 2; i++) {
            for (int j = 0; j < 2; j++) {
                result[i][j] = multiply(matrix[i][0], state[0][j]) ^ multiply(matrix[i][1], state[1][j]);
            }
        }

        return result;
    }


    // 轮密钥加函数1
    public static int[][] addRoundKey(int[][] state, int[][] key) {
        int[][] result = new int[2][2];

        for (int i = 0; i < 2; i++) {
            for (int j = 0; j < 2; j++) {
                result[i][j] = (state[i][j] ^ key[i][j]) & 0xF; // 确保结果在4位范围内
            }
        }

        return result;
    }



    // 密钥扩展函数
    public static int[][][] keyExpansion(int[][] key) {
        // 密钥的 4 字节分为两个字 w0 和 w1
        int[][] w = new int[6][2];  // 6个 2字节的密钥字 w0-w5

        // w0 和 w1 来自输入密钥的前 4 个字节
        w[0][0] = key[0][0] ;
        w[0][1] = key[1][0] ;
        w[1][0] = key[0][1] ;
        w[1][1] = key[1][1] ;

        // 计算 w2 = w0 ⊕ RCON[1] ⊕ SubNib(RotNib(w1))
        w[2] = xorWords(w[0], xorWords(rCON[0], subNib(rotNib(w[1]))));

        // 计算 w3 = w2 ⊕ w1
        w[3] = xorWords(w[2], w[1]);

        // 计算 w4 = w2 ⊕ RCON[2] ⊕ SubNib(RotNib(w3))
        w[4] = xorWords(w[2], xorWords(rCON[1], subNib(rotNib(w[3]))));

        // 计算 w5 = w4 ⊕ w3
        w[5] = xorWords(w[4], w[3]);

        // 将密钥分为轮密钥矩阵 (每个轮密钥由 2x2 的字节矩阵组成)
        int[][][] roundKeys = {
                {{w[0][0], w[1][0]}, {w[0][1], w[1][1]}},  // 轮密钥 0
                {{w[2][0], w[3][0]}, {w[2][1], w[3][1]}},  // 轮密钥 1
                {{w[4][0], w[5][0]}, {w[4][1], w[5][1]}}   // 轮密钥 2
        };

        return roundKeys;
    }

    // 字节旋转 RotNib (将 2 字节中的位左移)
    public static int[] rotNib(int[] word) {
        return new int[]{word[1], word[0]};
    }

    // 字节替代 SubNib (使用 S 盒替换字节)
    public static int[] subNib(int[] word) {
        // 假设 word 数组的长度为 2，且每个元素为 4 位（即 0 到 15）
        int[] result = new int[word.length];  // 用于存储替换后的结果

        for (int i = 0; i < word.length; i++) {
            // 将字节值分解为高 4 位和低 4 位
            int upperNibble = (word[i] >> 2) & 0x03;  // 高 2 位
            int lowerNibble = word[i] & 0x03;          // 低 2 位

            // 使用 SBOX 替换
            result[i] = SBOX[upperNibble][lowerNibble]; // SBOX 是定义好的替换矩阵
        }

        return result; // 返回替换后的结果
    }



    // 对输入的字应用 RCON
    public static int[] applyRCON(int round) {
        return new int[]{RCON[round - 1], 0x00}; // RCON 仅应用在高位字节
    }

    // 按位异或两个字（2字节）
    public static int[] xorWords(int[] w1, int[] w2) {
        return new int[]{w1[0] ^ w2[0], w1[1] ^ w2[1]};
    }


    // 有限域 GF(2^4) 中的乘法
    public static int multiply(int a, int b) {
        int product = 0;
        int modulus = 0b10011; // x^4 + x + 1 in binary (10011)

        for (int i = 0; i < 4; i++) {
            if ((b & 1) != 0) {
                product ^= a; // 如果当前位是1，将a加到product上
            }
            boolean carry = (a & 0x8) != 0; // 检查a的最高位是否为1
            a <<= 1; // 左移a，乘以x
            if (carry) {
                a ^= modulus; // 如果需要，进行模多项式归约
            }
            b >>= 1; // 右移b，处理下一个位
        }

        return product & 0xF; // 确保返回4位结果
    }





    // 将16位二进制字符串转换为2x2的十六进制状态矩阵
    public static int[][] convertToStateMatrix(String binaryInput) {
        int[][] state = new int[2][2];

        // 确保输入长度为16位，如果不足，则抛出异常
        if (binaryInput.length() != 16) {
            throw new IllegalArgumentException("输入必须是16位二进制字符串");
        }

        // 每4位一个元素，将其转换为十六进制并填充到2x2矩阵中
        for (int i = 0; i < 4; i++) {
            String nibble = binaryInput.substring(i * 4, (i * 4) + 4); // 取4位
            state[i % 2][i / 2] = Integer.parseInt(nibble, 2); // 列优先，转化为十六进制
        }

        return state;
    }

    // 将状态矩阵转换为字符串
    public static String convertStateMatrixToString(int[][] state) {
        StringBuilder binaryString = new StringBuilder();
        for (int j = 0; j < 2; j++) { // 列优先
            for (int i = 0; i < 2; i++) {
                String binary = String.format("%4s", Integer.toBinaryString(state[i][j])).replace(' ', '0');
                binaryString.append(binary);
            }
        }
        return binaryString.toString();
    }


    // 中间相遇攻击实现
    public static String[] meetInTheMiddle(String plaintext, String ciphertext) {
        Map<String, String> encryptionMap = new HashMap<>();  // 加密映射表
        Map<String, String> decryptionMap = new HashMap<>();  // 解密映射表

        // 假设所有可能的密钥可以枚举
        String[] allKeys = generateAllPossibleKeys();
        System.out.println(plaintext);
        // 将输入的明文和密文转换为状态矩阵
        int[][] plaintextState = convertToStateMatrix(plaintext);
        int[][] ciphertextState = convertToStateMatrix(ciphertext);

        // 第一步：构建加密映射表
        for (String k1 : allKeys) {
            int[][] keyMatrix1 = convertToStateMatrix(k1);
            int[][] intermediateState = encrypt(plaintextState, keyMatrix1);  // E_K1(P)
            String intermediateString = convertStateMatrixToString(intermediateState);
            encryptionMap.put(intermediateString, k1);  // 存储中间态和对应的 K1
        }

        // 第二步：构建解密映射表
        for (String k2 : allKeys) {
            int[][] keyMatrix2 = convertToStateMatrix(k2);
            int[][] intermediateState = decrypt(ciphertextState, keyMatrix2);  // D_K2(C)
            String intermediateString = convertStateMatrixToString(intermediateState);
            decryptionMap.put(intermediateString, k2);  // 存储中间态和对应的 K2
        }

        // 第三步：匹配中间态
        for (String intermediateState : encryptionMap.keySet()) {
            if (decryptionMap.containsKey(intermediateState)) {
                String k1 = encryptionMap.get(intermediateState);
                String k2 = decryptionMap.get(intermediateState);
                return new String[]{k1, k2};  // 返回匹配的 K1 和 K2
            }
        }

        return null;  // 未找到匹配的密钥对
    }

    // 生成所有可能的16位二进制密钥
    public static String[] generateAllPossibleKeys() {
        int numberOfKeys = 1 << 16; // 2^16 个可能的密钥
        String[] keys = new String[numberOfKeys];

        for (int i = 0; i < numberOfKeys; i++) {
            // 将整数转换为带有前导零的16位二进制字符串
            keys[i] = String.format("%16s", Integer.toBinaryString(i)).replace(' ', '0'); // 生成16位二进制字符串
        }

        return keys;
    }

    // 生成初始向量
    public static String generateIV() {
        SecureRandom random = new SecureRandom();
        int iv = random.nextInt(1 << 16); // 生成 0 到 65535 之间的随机数
        return String.format("%16s", Integer.toBinaryString(iv)).replace(' ', '0'); // 转换为16位二进制字符串，前导零补齐
    }



    // 将输入的二进制字符串转换为分组块（每16位一组）
    public static int[][][] convertBinaryStringToBlocks(String binaryString) {
        int blockSize = 16; // 每个块16位
        int numBlocks = binaryString.length() / blockSize; // 计算块的数量
        int[][][] blocks = new int[numBlocks][2][2]; // 三维数组，每个块是2x2的状态矩阵

        // 将字符串每16位一组，转换为状态矩阵并存入blocks
        for (int i = 0; i < numBlocks; i++) {
            String block = binaryString.substring(i * blockSize, (i + 1) * blockSize); // 取16位
            blocks[i] = convertToStateMatrix(block); // 将16位二进制字符串转换为状态矩阵
        }

        return blocks;
    }



    // CBC 加密方法
    public static String cbcEncrypt(String plaintextBinary, int[][] key,String iv) {
        // 1. 生成 IV 并转换为状态矩阵
        int[][] IV = convertToStateMatrix(iv);

        // 2. 将明文二进制字符串转换为状态矩阵块
        int[][][] plaintextBlocks = convertBinaryStringToBlocks(plaintextBinary);

        // 3. 创建密文块数组用于存储每一个加密块
        int[][][] ciphertextBlocks = new int[plaintextBlocks.length][2][2];

        // 4. 初始化前一个块为 IV
        int[][] previousBlock = IV;

        // 5. 开始加密每一个明文块
        for (int i = 0; i < plaintextBlocks.length; i++) {
            // 5.1. 明文块与前一个块按位异或
            int[][] currentBlock = xorStateMatrices(plaintextBlocks[i], previousBlock);

            // 5.2. 使用 S-AES 进行加密
            int[][] encryptedBlock = encrypt(currentBlock, key);

            // 5.3. 存储加密后的密文块
            ciphertextBlocks[i] = encryptedBlock;

            // 5.4. 更新前一个块为当前密文块
            previousBlock = encryptedBlock;
        }

        // 6. 将每个密文块转换为二进制字符串并拼接
        StringBuilder ciphertextBinary = new StringBuilder();
        for (int i = 0; i < ciphertextBlocks.length; i++) {
            ciphertextBinary.append(convertStateMatrixToString(ciphertextBlocks[i]));
        }

        // 7. 返回最终的密文二进制字符串
        return ciphertextBinary.toString();
    }

    // 按位异或两个状态矩阵
    public static int[][] xorStateMatrices(int[][] matrix1, int[][] matrix2) {
        int[][] result = new int[2][2];
        for (int i = 0; i < 2; i++) {
            for (int j = 0; j < 2; j++) {
                result[i][j] = matrix1[i][j] ^ matrix2[i][j]; // 按位异或
            }
        }
        return result;
    }

    // CBC 解密方法
    public static String cbcDecrypt(String ciphertextBinary, int[][] key, String iv) {
        // 1. 将密文二进制字符串转换为状态矩阵块
        int[][][] ciphertextBlocks = convertBinaryStringToBlocks(ciphertextBinary); // 需要实现该方法

        // 2. 初始化前一个块为 IV
        int[][] previousBlock = convertToStateMatrix(iv);

        // 3. 创建明文块数组用于存储每一个解密块
        int[][][] plaintextBlocks = new int[ciphertextBlocks.length][2][2];

        // 4. 开始解密每一个密文块
        for (int i = 0; i < ciphertextBlocks.length; i++) {
            // 4.1. 使用 S-AES 进行解密
            int[][] decryptedBlock = decrypt(ciphertextBlocks[i], key);

            // 4.2. 解密后的块与前一个块按位异或
            plaintextBlocks[i] = xorStateMatrices(decryptedBlock, previousBlock);

            // 4.3. 更新前一个块为当前密文块
            previousBlock = ciphertextBlocks[i];
        }

        // 5. 将每个明文块转换为二进制字符串并拼接
        StringBuilder plaintextBinary = new StringBuilder();
        for (int i = 0; i < plaintextBlocks.length; i++) {
            plaintextBinary.append(convertStateMatrixToString(plaintextBlocks[i]));
        }

        // 6. 返回最终的明文二进制字符串
        return plaintextBinary.toString();
    }




}
