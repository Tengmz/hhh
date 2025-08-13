/**
 * SM2密钥生成器测试类
 */
public class SM2KeyGeneratorTest {
    
    public static void main(String[] args) {
        System.out.println("=== SM2密钥生成器测试 ===\n");
        
        // 测试基本密钥生成功能
        testBasicKeyGeneration();
        
        // 测试多次生成密钥的随机性
        testKeyRandomness();
        
        // 测试密钥格式
        testKeyFormat();
        
        System.out.println("所有测试完成！");
    }
    
    /**
     * 测试基本密钥生成功能
     */
    private static void testBasicKeyGeneration() {
        System.out.println("1. 基本密钥生成测试");
        System.out.println("-------------------");
        
        SM2KeyGenerator keyGen = new SM2KeyGenerator();
        SM2KeyGenerator.SM2KeyPair keyPair = keyGen.generateKeyPair();
        
        System.out.println("生成的SM2密钥对：");
        System.out.println(keyPair);
        
        // 验证密钥不为空
        if (keyPair.getPrivateKey() != null && keyPair.getPublicKey() != null) {
            System.out.println("✓ 密钥生成成功");
        } else {
            System.out.println("✗ 密钥生成失败");
        }
        
        // 验证私钥长度
        String privateKeyHex = keyPair.getPrivateKeyHex();
        if (privateKeyHex.length() == 64) {
            System.out.println("✓ 私钥长度正确 (64位十六进制)");
        } else {
            System.out.println("✗ 私钥长度错误: " + privateKeyHex.length());
        }
        
        // 验证公钥长度（非压缩格式）
        String publicKeyHex = keyPair.getPublicKeyHex();
        if (publicKeyHex.length() == 130 && publicKeyHex.startsWith("04")) {
            System.out.println("✓ 公钥格式正确 (130位十六进制，非压缩格式)");
        } else {
            System.out.println("✗ 公钥格式错误: 长度=" + publicKeyHex.length() + ", 前缀=" + publicKeyHex.substring(0, 2));
        }
        
        System.out.println();
    }
    
    /**
     * 测试密钥生成的随机性
     */
    private static void testKeyRandomness() {
        System.out.println("2. 密钥随机性测试");
        System.out.println("----------------");
        
        SM2KeyGenerator keyGen = new SM2KeyGenerator();
        
        // 生成多个密钥对
        SM2KeyGenerator.SM2KeyPair keyPair1 = keyGen.generateKeyPair();
        SM2KeyGenerator.SM2KeyPair keyPair2 = keyGen.generateKeyPair();
        SM2KeyGenerator.SM2KeyPair keyPair3 = keyGen.generateKeyPair();
        
        System.out.println("密钥对1私钥: " + keyPair1.getPrivateKeyHex());
        System.out.println("密钥对2私钥: " + keyPair2.getPrivateKeyHex());
        System.out.println("密钥对3私钥: " + keyPair3.getPrivateKeyHex());
        
        // 验证私钥不相同
        boolean allDifferent = !keyPair1.getPrivateKey().equals(keyPair2.getPrivateKey()) &&
                              !keyPair1.getPrivateKey().equals(keyPair3.getPrivateKey()) &&
                              !keyPair2.getPrivateKey().equals(keyPair3.getPrivateKey());
        
        if (allDifferent) {
            System.out.println("✓ 生成的私钥各不相同，随机性良好");
        } else {
            System.out.println("✗ 生成的私钥存在重复，随机性不足");
        }
        
        System.out.println();
    }
    
    /**
     * 测试密钥格式和有效性
     */
    private static void testKeyFormat() {
        System.out.println("3. 密钥格式测试");
        System.out.println("---------------");
        
        SM2KeyGenerator keyGen = new SM2KeyGenerator();
        SM2KeyGenerator.SM2KeyPair keyPair = keyGen.generateKeyPair();
        
        // 测试私钥格式
        String privateKeyHex = keyPair.getPrivateKeyHex();
        boolean isValidHex = privateKeyHex.matches("[0-9A-F]+");
        
        System.out.println("私钥十六进制: " + privateKeyHex);
        System.out.println("私钥是否为有效十六进制: " + (isValidHex ? "✓" : "✗"));
        
        // 测试公钥格式
        String publicKeyHex = keyPair.getPublicKeyHex();
        boolean isValidPublicKey = publicKeyHex.matches("04[0-9A-F]{128}");
        
        System.out.println("公钥十六进制: " + publicKeyHex);
        System.out.println("公钥格式是否正确: " + (isValidPublicKey ? "✓" : "✗"));
        
        // 提取公钥坐标
        if (publicKeyHex.startsWith("04") && publicKeyHex.length() == 130) {
            String xCoord = publicKeyHex.substring(2, 66);
            String yCoord = publicKeyHex.substring(66, 130);
            
            System.out.println("公钥X坐标: " + xCoord);
            System.out.println("公钥Y坐标: " + yCoord);
        }
        
        System.out.println();
    }
    
    /**
     * 演示如何使用SM2密钥生成器
     */
    public static void demonstrateUsage() {
        System.out.println("=== SM2密钥生成器使用示例 ===\n");
        
        // 创建密钥生成器
        SM2KeyGenerator keyGenerator = new SM2KeyGenerator();
        
        // 生成密钥对
        SM2KeyGenerator.SM2KeyPair keyPair = keyGenerator.generateKeyPair();
        
        // 获取私钥和公钥
        String privateKey = keyPair.getPrivateKeyHex();
        String publicKey = keyPair.getPublicKeyHex();
        
        System.out.println("生成的SM2密钥对：");
        System.out.println("私钥: " + privateKey);
        System.out.println("公钥: " + publicKey);
        
        // 也可以获取原始的BigInteger和ECPoint对象
        System.out.println("\n原始对象：");
        System.out.println("私钥 (BigInteger): " + keyPair.getPrivateKey());
        System.out.println("公钥 (ECPoint): " + keyPair.getPublicKey());
    }
}