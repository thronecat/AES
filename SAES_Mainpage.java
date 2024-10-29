package S_AES1;



import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Random;

import static S_AES1.AES_Methods.*;
import static S_AES1.AES_Methods.cbcEncrypt;

//主页面
public class SAES_Mainpage extends JFrame {
    private JButton encryptButton;
    private JButton multiplyButton;
    private JButton decodeButton;
    private JButton ASCIIButton;

    public SAES_Mainpage() {
        // 设置窗口标题
        setTitle("S-AES 加解密工具");
        setSize(400, 250);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        // 设置布局
        // 设置布局为 GridBagLayout
        setLayout(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();

        // 创建按钮
        encryptButton = new JButton("普通加解密");
        encryptButton.setPreferredSize(new Dimension(150, 30));
        ASCIIButton = new JButton("ASCII码加解密");
        ASCIIButton.setPreferredSize(new Dimension(150, 30));
        multiplyButton = new JButton("多重加解密");
        multiplyButton.setPreferredSize(new Dimension(150, 30));
        decodeButton = new JButton("工作模式");
        decodeButton.setPreferredSize(new Dimension(150, 30));

        // 设置按钮位置
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.insets = new Insets(10, 10, 10, 10); // 设置按钮之间的间距
        gbc.anchor = GridBagConstraints.CENTER; // 使按钮居中
        add(encryptButton, gbc);

        gbc.gridy = 1;
        add(ASCIIButton, gbc);

        gbc.gridy = 2;
        add(multiplyButton, gbc);

        gbc.gridy = 3;
        add(decodeButton, gbc);



        // 加密按钮事件监听
        encryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                new SAES_en().setVisible(true);
                dispose();
            }
        });

        //解密
        ASCIIButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                new SAES_en_ASCII().setVisible(true);
                dispose();
            }
        });

        // 破解按钮的事件监听
        decodeButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                new CBCModePage().setVisible(true);
                dispose();

            }
        });

        // 多重加解密按钮的事件监听
        multiplyButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                new SAES_multiple().setVisible(true);
                dispose();

            }
        });

    }
    public static void main(String[] args) {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                new S_AES1.SAES_Mainpage().setVisible(true);
            }
        });
    }
}

class SAES_en extends JFrame {

    // GUI Components
    private JTextField inputField;
    private JTextField outputField;
    private JTextField keyField;
    private JButton encryptButton;
    private JButton decryptButton;
    private JButton generateKeyButton;
    private JButton backButton;

    public SAES_en() {
        // 设置窗口标题
        setTitle("S-AES 加解密算法");
        setSize(400, 250);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        // 设置布局
        setLayout(new GridLayout(6, 2));

        // 创建并添加组件
        add(new JLabel("密钥 (16位二进制):"));
        keyField = new JTextField(16);
        add(keyField);

        add(new JLabel("输入 (16位二进制):"));
        inputField = new JTextField(16);
        add(inputField);

        add(new JLabel("输出结果 (二进制):"));
        outputField = new JTextField();
        outputField.setEditable(false);
        add(outputField);

        encryptButton = new JButton("加密");
        decryptButton = new JButton("解密");
        generateKeyButton = new JButton("随机生成密钥");
        backButton = new JButton("返回");

        add(encryptButton);
        add(decryptButton);
        add(generateKeyButton);
        add(backButton);

        // 加密按钮事件监听
        encryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String input = inputField.getText().trim();
                String keyInput = keyField.getText().trim(); // 获取用户输入的密钥
                if (validateInput(keyInput, input, 16, 16)) {
                    int[][] state = convertToStateMatrix(input);
                    int[][] key = convertToStateMatrix(keyInput); // 将密钥转换为矩阵
                    int[][] encrypted = encrypt(state, key);

                    String result = convertStateMatrixToString(encrypted);
                    System.out.println("Encrypted State: " + result); // Debug
                    outputField.setText(result);
                } else {
                    JOptionPane.showMessageDialog(SAES_en.this, "请输入正确的16位二进制密钥和16位明文。", "输入错误", JOptionPane.ERROR_MESSAGE);
                }
            }
        });

        // 解密按钮事件监听
        decryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String input = inputField.getText().trim();
                String keyInput = keyField.getText().trim(); // 获取用户输入的密钥
                if (validateInput(keyInput, input, 16, 16)) {
                    int[][] state = convertToStateMatrix(input);
                    int[][] key = convertToStateMatrix(keyInput); // 将密钥转换为矩阵
                    int[][] decrypted = decrypt(state, key);
                    String result = convertStateMatrixToString(decrypted);
                    System.out.println("Decrypted State: " + result); // Debug
                    outputField.setText(result);
                } else {
                    JOptionPane.showMessageDialog(SAES_en.this, "请输入正确的16位二进制密钥和16位密文。", "输入错误", JOptionPane.ERROR_MESSAGE);
                }
            }
        });

        // 随机生成密钥按钮的事件监听
        generateKeyButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String randomKey = generateRandomKey(16);
                keyField.setText(randomKey);
                JOptionPane.showMessageDialog(SAES_en.this, "生成的随机密钥: " + randomKey, "随机密钥生成", JOptionPane.INFORMATION_MESSAGE);
            }
        });

        // 返回按钮的事件监听
        backButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                new SAES_Mainpage().setVisible(true); // 回到主页面
                dispose(); // 关闭当前窗口
            }
        });
    }

    // 验证输入是否是二进制且长度正确
    private boolean validateInput(String key, String text, int keyLength, int textLength) {
        return key.matches("[01]{" + keyLength + "}") && text.matches("[01]{" + textLength + "}");
    }

    // 生成随机的二进制密钥
    private String generateRandomKey(int length) {
        Random random = new Random();
        StringBuilder key = new StringBuilder();
        for (int i = 0; i < length; i++) {
            key.append(random.nextInt(2)); // 生成0或1
        }
        return key.toString();
    }

    // 将二进制字符串转换为状态矩阵
    // 将输入字符串（明文或密文）转换为状态矩阵




}



class SAES_multiple extends JFrame {

    private JButton twoWayEncryptionButton;   // 二重加解密按钮
    private JButton meetInTheMiddleAttackButton; // 中间相遇攻击按钮
    private JButton threeWayEncryptionButton; // 三重加解密按钮
    private JButton backButton;

    public SAES_multiple() {
        setTitle("S-AES 扩展加解密工具");
        setSize(400, 300);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        // 设置布局
        setLayout(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        //setLayout(new GridLayout(4, 1));

        // 创建并添加按钮
        twoWayEncryptionButton = new JButton("二重加解密");
        twoWayEncryptionButton.setPreferredSize(new Dimension(150, 30));
        meetInTheMiddleAttackButton = new JButton("中间相遇攻击");
        meetInTheMiddleAttackButton.setPreferredSize(new Dimension(150, 30));
        threeWayEncryptionButton = new JButton("三重加解密");
        threeWayEncryptionButton.setPreferredSize(new Dimension(150, 30));
        backButton = new JButton("返回");
        backButton.setPreferredSize(new Dimension(150, 30));

        // 设置按钮位置
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.insets = new Insets(10, 10, 10, 10); // 设置按钮之间的间距
        gbc.anchor = GridBagConstraints.CENTER; // 使按钮居中
        add(twoWayEncryptionButton, gbc);

        gbc.gridy = 1;
        add(meetInTheMiddleAttackButton, gbc);

        gbc.gridy = 2;
        add(threeWayEncryptionButton, gbc);

        gbc.gridy = 3;
        add(backButton, gbc);




        // 二重加解密按钮事件监听器
        twoWayEncryptionButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                new SAES_en2().setVisible(true);  // 打开二重加解密页面
                dispose();  // 关闭当前页面
            }
        });

        // 中间相遇攻击按钮事件监听器
        meetInTheMiddleAttackButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                new MeetInTheMiddleAttackPage().setVisible(true);  // 打开中间相遇攻击页面
                dispose();  // 关闭当前页面
            }
        });

        // 三重加解密按钮事件监听器
        threeWayEncryptionButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                new SAES_en3().setVisible(true);  // 打开三重加解密页面
                dispose();  // 关闭当前页面
            }
        });

        backButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                new SAES_Mainpage().setVisible(true);  // 打开三重加解密页面
                dispose();  // 关闭当前页面
            }
        });

    }
}

class SAES_en2 extends JFrame {

    // GUI Components
    private JTextField inputField;
    private JTextField outputField;
    private JTextField keyField;
    private JButton encryptButton;
    private JButton decryptButton;
    private JButton generateKeyButton;
    private JButton backButton;

    public SAES_en2() {
        // 设置窗口标题
        setTitle("S-AES 双重加密算法");
        setSize(500, 250);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        // 设置布局
        setLayout(new GridLayout(6, 2));

        // 创建并添加组件
        add(new JLabel("密钥 (32位二进制):"));
        keyField = new JTextField(32);
        add(keyField);

        add(new JLabel("输入 (16位二进制):"));
        inputField = new JTextField(16);
        add(inputField);

        add(new JLabel("输出结果:"));
        outputField = new JTextField();
        outputField.setEditable(false);
        add(outputField);

        encryptButton = new JButton("加密");
        decryptButton = new JButton("解密");
        generateKeyButton = new JButton("随机生成密钥");
        backButton = new JButton("返回");

        add(encryptButton);
        add(decryptButton);
        add(generateKeyButton);
        add(backButton);

        // 加密按钮事件监听
        encryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String input = inputField.getText().trim();
                String keyInput = keyField.getText().trim();
                if (validateInput(keyInput, input, 32, 16)) {
                    // 获取32位密钥并拆分为两个16位子密钥
                    String key1 = keyInput.substring(0, 16);
                    String key2 = keyInput.substring(16);

                    // 第一次加密
                    int[][] state = convertToStateMatrix(input);
                    int[][] keyMatrix1 = convertToStateMatrix(key1);
                    int[][] encrypted1 = encrypt(state, keyMatrix1);

                    // 第二次加密
                    int[][] keyMatrix2 = convertToStateMatrix(key2);
                    int[][] encrypted2 = encrypt(encrypted1, keyMatrix2);

                    outputField.setText(convertStateMatrixToString(encrypted2));
                } else {
                    JOptionPane.showMessageDialog(SAES_en2.this, "请输入正确的32位密钥和16位明文。", "输入错误", JOptionPane.ERROR_MESSAGE);
                }
            }
        });

        // 解密按钮事件监听
        decryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String input = inputField.getText().trim();
                String keyInput = keyField.getText().trim();
                if (validateInput(keyInput, input, 32, 16)) {
                    // 获取32位密钥并拆分为两个16位子密钥
                    String key1 = keyInput.substring(0, 16);
                    String key2 = keyInput.substring(16);

                    // 第一次解密
                    int[][] state = convertToStateMatrix(input);
                    int[][] keyMatrix2 = convertToStateMatrix(key2);
                    int[][] decrypted1 = decrypt(state, keyMatrix2);

                    // 第二次解密
                    int[][] keyMatrix1 = convertToStateMatrix(key1);
                    int[][] decrypted2 = decrypt(decrypted1, keyMatrix1);

                    outputField.setText(convertStateMatrixToString(decrypted2));
                } else {
                    JOptionPane.showMessageDialog(SAES_en2.this, "请输入正确的32位密钥和16位密文。", "输入错误", JOptionPane.ERROR_MESSAGE);
                }
            }
        });

        // 随机生成密钥按钮的事件监听
        generateKeyButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String randomKey = generateRandomKey(32);
                keyField.setText(randomKey);
                JOptionPane.showMessageDialog(SAES_en2.this, "生成的随机密钥: " + randomKey, "随机密钥生成", JOptionPane.INFORMATION_MESSAGE);
            }
        });

        // 返回按钮的事件监听
        backButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                new SAES_multiple().setVisible(true); // 假设有主页面
                dispose(); // 关闭当前窗口
            }
        });
    }

    // 验证输入是否是二进制且长度正确
    private boolean validateInput(String key, String text, int keyLength, int textLength) {
        return key.matches("[01]{" + keyLength + "}") && text.matches("[01]{" + textLength + "}");
    }

    // 生成随机的二进制密钥
    private String generateRandomKey(int length) {
        Random random = new Random();
        StringBuilder key = new StringBuilder();
        for (int i = 0; i < length; i++) {
            key.append(random.nextInt(2)); // 生成0或1
        }
        return key.toString();
    }
}


class SAES_en3 extends JFrame {

    // GUI Components
    private JTextField inputField;
    private JTextField outputField;
    private JTextField keyField;
    private JButton encryptButton;
    private JButton decryptButton;
    private JButton generateKeyButton;
    private JButton backButton;

    public SAES_en3() {
        // 设置窗口标题
        setTitle("S-AES 三重加密算法");
        setSize(500, 250);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        // 设置布局
        setLayout(new GridLayout(6, 2));

        // 创建并添加组件
        add(new JLabel("密钥 (48位二进制):"));
        keyField = new JTextField(32);
        add(keyField);

        add(new JLabel("输入 (16位二进制):"));
        inputField = new JTextField(16);
        add(inputField);

        add(new JLabel("输出结果:"));
        outputField = new JTextField();
        outputField.setEditable(false);
        add(outputField);

        encryptButton = new JButton("加密");
        decryptButton = new JButton("解密");
        generateKeyButton = new JButton("随机生成密钥");
        backButton = new JButton("返回");

        add(encryptButton);
        add(decryptButton);
        add(generateKeyButton);
        add(backButton);

        // 加密按钮事件监听
        encryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String input = inputField.getText().trim();
                String keyInput = keyField.getText().trim();
                if (validateInput(keyInput, input, 48, 16)) {
                    // 获取48位密钥并拆分为三个16位子密钥
                    String key1 = keyInput.substring(0, 16);
                    String key2 = keyInput.substring(16,32);
                    String key3 = keyInput.substring(32);

                    // 第一次加密
                    int[][] state = convertToStateMatrix(input);
                    int[][] keyMatrix1 = convertToStateMatrix(key1);
                    int[][] encrypted1 = encrypt(state, keyMatrix1);

                    // 第二次加密
                    int[][] keyMatrix2 = convertToStateMatrix(key2);
                    int[][] encrypted2 = encrypt(encrypted1, keyMatrix2);

                    //第三次加密
                    int[][] keyMatrix3 = convertToStateMatrix(key3);
                    int[][] encrypted3 = encrypt(encrypted2, keyMatrix3);

                    outputField.setText(convertStateMatrixToString(encrypted3));
                } else {
                    JOptionPane.showMessageDialog(SAES_en3.this, "请输入正确的48位密钥和16位明文。", "输入错误", JOptionPane.ERROR_MESSAGE);
                }
            }
        });

        // 解密按钮事件监听
        decryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String input = inputField.getText().trim();
                String keyInput = keyField.getText().trim();

                // 检查是否为48位密钥和16位密文
                if (validateInput(keyInput, input, 48, 16)) {
                    // 获取48位密钥并拆分为三个16位子密钥
                    String key1 = keyInput.substring(0, 16);
                    String key2 = keyInput.substring(16, 32);
                    String key3 = keyInput.substring(32);

                    // 第一次解密（使用Key3）
                    int[][] state = convertToStateMatrix(input);
                    int[][] keyMatrix3 = convertToStateMatrix(key3);
                    int[][] decrypted1 = decrypt(state, keyMatrix3);

                    // 第二次解密（使用Key2）
                    int[][] keyMatrix2 = convertToStateMatrix(key2);
                    int[][] decrypted2 = decrypt(decrypted1, keyMatrix2);

                    // 第三次解密（使用Key1）
                    int[][] keyMatrix1 = convertToStateMatrix(key1);
                    int[][] decrypted3 = decrypt(decrypted2, keyMatrix1);

                    // 将结果显示在输出框中
                    outputField.setText(convertStateMatrixToString(decrypted3));
                } else {
                    JOptionPane.showMessageDialog(SAES_en3.this, "请输入正确的48位密钥和16位密文。", "输入错误", JOptionPane.ERROR_MESSAGE);
                }
            }
        });


        // 随机生成密钥按钮的事件监听
        generateKeyButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String randomKey = generateRandomKey(48);
                keyField.setText(randomKey);
                JOptionPane.showMessageDialog(SAES_en3.this, "生成的随机密钥: " + randomKey, "随机密钥生成", JOptionPane.INFORMATION_MESSAGE);
            }
        });

        // 返回按钮的事件监听
        backButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                new SAES_multiple().setVisible(true); // 假设有主页面
                dispose(); // 关闭当前窗口
            }
        });
    }

    // 验证输入是否是二进制且长度正确
    private boolean validateInput(String key, String text, int keyLength, int textLength) {
        return key.matches("[01]{" + keyLength + "}") && text.matches("[01]{" + textLength + "}");
    }

    // 生成随机的二进制密钥
    private String generateRandomKey(int length) {
        Random random = new Random();
        StringBuilder key = new StringBuilder();
        for (int i = 0; i < length; i++) {
            key.append(random.nextInt(2)); // 生成0或1
        }
        return key.toString();
    }
}


class MeetInTheMiddleAttackPage extends JFrame {

    private JTextField plaintextField;
    private JTextField ciphertextField;
    private JTextArea resultArea;
    private JButton attackButton;
    private JButton backButton;

    public MeetInTheMiddleAttackPage() {
        setTitle("中间相遇攻击");
        setSize(400, 300);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        // 设置布局
        setLayout(new BorderLayout());

        // 创建输入面板
        JPanel inputPanel = new JPanel(new GridLayout(3, 2));

        inputPanel.add(new JLabel("明文 (16位二进制):"));
        plaintextField = new JTextField();
        inputPanel.add(plaintextField);

        inputPanel.add(new JLabel("密文 (16位二进制):"));
        ciphertextField = new JTextField();
        inputPanel.add(ciphertextField);

        attackButton = new JButton("执行中间相遇攻击");
        inputPanel.add(attackButton);

        backButton = new JButton("返回");
        inputPanel.add(backButton);

        add(inputPanel, BorderLayout.NORTH);

        // 创建结果区域
        resultArea = new JTextArea();
        resultArea.setEditable(false);
        add(new JScrollPane(resultArea), BorderLayout.CENTER);

        // 按钮事件监听
        attackButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String plaintext = plaintextField.getText().trim();
                String ciphertext = ciphertextField.getText().trim();

                // 调用中间相遇攻击方法
                String[] keys = meetInTheMiddle(plaintext, ciphertext);

                // 显示结果
                if (keys != null) {
                    resultArea.setText("找到的密钥对:\n");
                    for (String key : keys) {
                        resultArea.append(key + "\n");
                    }
                } else {
                    resultArea.setText("未找到匹配的密钥对");
                }
            }
        });

        // 返回按钮的事件监听
        backButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                new SAES_multiple().setVisible(true); // 假设有主页面
                dispose(); // 关闭当前窗口
            }
        });
    }
}

class SAES_en_ASCII extends JFrame {

    // GUI Components
    private JTextField inputField;
    private JTextField outputField;
    private JTextField keyField;
    private JButton encryptButton;
    private JButton decryptButton;
    private JButton generateKeyButton;
    private JButton backButton;

    public SAES_en_ASCII() {
        // 设置窗口标题
        setTitle("S-AES 加解密算法");
        setSize(400, 250);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        // 设置布局
        setLayout(new GridLayout(6, 2));

        // 创建并添加组件
        add(new JLabel("密钥 :"));
        keyField = new JTextField(4);
        add(keyField);

        add(new JLabel("输入 (ASCII 字符串):"));
        inputField = new JTextField(4);
        add(inputField);

        add(new JLabel("输出结果 (ASCII 字符串):"));
        outputField = new JTextField();
        outputField.setEditable(false);
        add(outputField);

        encryptButton = new JButton("加密");
        decryptButton = new JButton("解密");
        generateKeyButton = new JButton("随机生成密钥");
        backButton = new JButton("返回");

        add(encryptButton);
        add(decryptButton);
        add(generateKeyButton);
        add(backButton);

        // 加密按钮事件监听
        encryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String input = inputField.getText().trim();
                String keyInput = keyField.getText().trim(); // 获取用户输入的密钥

                    int[][] state = convertToStateMatrix_ascii(input); // ASCII 转矩阵
                    int[][] key = convertToStateMatrix(keyInput); // 将密钥转换为矩阵
                    int[][] encrypted = encrypt(state, key);
                    outputField.setText(convertStateMatrixToString_ascii(encrypted, true)); // 输出 ASCII

            }
        });

        // 解密按钮事件监听
        decryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String input = inputField.getText().trim();
                String keyInput = keyField.getText().trim(); // 获取用户输入的密钥

                    int[][] state = convertToStateMatrix_ascii(input); // ASCII 转矩阵
                    int[][] key = convertToStateMatrix(keyInput); // 将密钥转换为矩阵
                    int[][] decrypted = decrypt(state, key);
                    outputField.setText(convertStateMatrixToString_ascii(decrypted, true)); // 输出 ASCII

            }
        });

        // 随机生成密钥按钮的事件监听
        generateKeyButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String randomKey = generateRandomKey(16);
                keyField.setText(randomKey);
                JOptionPane.showMessageDialog(SAES_en_ASCII.this, "生成的随机密钥: " + randomKey, "随机密钥生成", JOptionPane.INFORMATION_MESSAGE);
            }
        });

        // 返回按钮的事件监听
        backButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                new SAES_Mainpage().setVisible(true); // 回到主页面
                dispose(); // 关闭当前窗口
            }
        });
    }

    // 验证输入是否是十六进制且长度正确
    private boolean validateInput(String key, String text, int keyLength, int textLength) {
        return key.matches("[0-9A-Fa-f]{" + keyLength + "}") && text.length() == textLength;
    }

    // 生成随机的二进制密钥
    private String generateRandomKey(int length) {
        Random random = new Random();
        StringBuilder key = new StringBuilder();
        for (int i = 0; i < length; i++) {
            key.append(random.nextInt(2)); // 生成0或1
        }
        return key.toString();
    }

    // 将 ASCII 字符串转换为状态矩阵
    private int[][] convertToStateMatrix_ascii(String input) {
        int[][] state = new int[2][2];
        byte[] bytes = input.getBytes(); // 获取 ASCII 字符的字节数组

        // 使用 StringBuilder 创建二进制字符串
        StringBuilder binaryStringBuilder = new StringBuilder();
        for (byte b : bytes) {
            // 将每个字节转换为二进制字符串，并填充0以确保每个字节都是8位
            String binary = String.format("%8s", Integer.toBinaryString(b & 0xFF)).replace(' ', '0');
            binaryStringBuilder.append(binary);

            // 如果二进制字符串长度超过 16 位，停止添加
            if (binaryStringBuilder.length() >= 16) {
                break;
            }
        }

        // 截取前 16 位并确保字符串长度为 16 位
        String binaryString = binaryStringBuilder.toString();
        if (binaryString.length() > 16) {
            binaryString = binaryString.substring(0, 16);
        } else if (binaryString.length() < 16) {
            // 如果不足 16 位，补充前导零
            binaryString = String.format("%16s", binaryString).replace(' ', '0');
        }

        // 将二进制字符串转换为状态矩阵
        state = convertToStateMatrix(binaryString);
        return state;
    }



    // 将状态矩阵转换为 ASCII 字符串
    private String convertStateMatrixToString_ascii(int[][] state, boolean isAscii) {
        String sb = convertStateMatrixToString(state);
        StringBuilder asciiBuilder = new StringBuilder();

        // 检查输入的二进制字符串长度
        if (sb.length() != 16) {
            throw new IllegalArgumentException("输入的二进制字符串必须是 16 位长");
        }

        // 将二进制字符串分成两个8位部分
        for (int i = 0; i < 16; i += 8) {
            String byteString = sb.substring(i, i + 8);
            // 将8位二进制字符串转换为ASCII码
            int ascii = Integer.parseInt(byteString, 2); // 以2为基数将二进制字符串转换为十进制
            // 将 ASCII 码转换为字符并添加到 StringBuilder
            asciiBuilder.append((char) ascii);
        }

        return asciiBuilder.toString(); // 返回构建的 ASCII 字符串
    }

}
class CBCModePage extends JFrame {

    private JTextArea inputArea;    // 输入区域（明文和密文）
    private JTextArea keyArea;       // 密钥输入区域
    private JTextArea ivArea;        // 初始向量输入区域
    private JTextArea resultArea;    // 输出区域
    private JButton encryptButton;    // 加密按钮
    private JButton decryptButton;    // 解密按钮
    private JButton randomKeyButton;  // 生成随机密钥按钮
    private JButton randomIVButton;   // 生成随机初始向量按钮
    private JButton backButton;       // 返回按钮

    public CBCModePage() {
        setTitle("CBC模式加解密");
        setSize(500, 500);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        // 设置布局
        setLayout(new BorderLayout());

        // 创建输入面板
        JPanel inputPanel = new JPanel(new GridLayout(3, 2)); // 输入区域从上到下排列
        inputPanel.add(new JLabel("输入 (明文或密文):"));
        inputArea = new JTextArea(5, 20); // 文本输入区域
        inputPanel.add(new JScrollPane(inputArea)); // 包裹在滚动面板中

        inputPanel.add(new JLabel("密钥:"));
        keyArea = new JTextArea(1, 20);
        inputPanel.add(new JScrollPane(keyArea));

        inputPanel.add(new JLabel("初始向量:"));
        ivArea = new JTextArea(1, 20);
        inputPanel.add(new JScrollPane(ivArea));

        add(inputPanel, BorderLayout.NORTH);

        // 创建按钮面板，第一行放加解密按钮，第二行放其他按钮
        JPanel buttonPanel = new JPanel(new GridLayout(2, 3, 5, 5)); // 两行三列
        encryptButton = new JButton("执行加密");
        buttonPanel.add(encryptButton);

        decryptButton = new JButton("执行解密");
        buttonPanel.add(decryptButton);

// 第二行的按钮
        randomKeyButton = new JButton("生成随机密钥");
        buttonPanel.add(randomKeyButton);

        randomIVButton = new JButton("生成随机初始向量");
        buttonPanel.add(randomIVButton);

        backButton = new JButton("返回");
        buttonPanel.add(backButton);
        add(buttonPanel, BorderLayout.CENTER);

        // 创建结果区域
        resultArea = new JTextArea();
        resultArea.setEditable(false); // 结果区域不可编辑
        resultArea.setLineWrap(true);
        resultArea.setWrapStyleWord(true);
        resultArea.setPreferredSize(new Dimension(500, 100)); // 增加输出框的高度
        add(new JScrollPane(resultArea), BorderLayout.SOUTH);

        // 加密按钮事件监听
        encryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String plaintext = inputArea.getText().trim(); // 读取输入区文本
                String key = keyArea.getText().trim();
                String iv = ivArea.getText().trim();

                // 调用 CBC 加密方法
                String ciphertext = cbcEncrypt(plaintext, convertToStateMatrix(key), iv);

                // 显示结果
                resultArea.setText("加密结果:\n" + ciphertext);
            }
        });

        // 解密按钮事件监听
        decryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String ciphertext = inputArea.getText().trim(); // 读取输入区文本
                String key = keyArea.getText().trim();
                String iv = ivArea.getText().trim();

                // 调用 CBC 解密方法
                String plaintext = cbcDecrypt(ciphertext, convertToStateMatrix(key), iv);

                // 显示结果
                resultArea.setText("解密结果:\n" + plaintext);
            }
        });

        // 随机密钥按钮的事件监听
        randomKeyButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String randomKey = generateRandomKey(16); // 生成16位二进制密钥
                keyArea.setText(randomKey);
            }
        });

        // 随机初始向量按钮的事件监听
        randomIVButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String randomIV = generateIV(); // 生成随机IV
                ivArea.setText(randomIV);
            }
        });

        // 返回按钮的事件监听
        backButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                new SAES_Mainpage().setVisible(true); // 假设有主页面
                dispose(); // 关闭当前窗口
            }
        });
    }

    // 生成随机的二进制密钥
    private String generateRandomKey(int length) {
        Random random = new Random();
        StringBuilder key = new StringBuilder();
        for (int i = 0; i < length; i++) {
            key.append(random.nextInt(2)); // 生成0或1
        }
        return key.toString();
    }}