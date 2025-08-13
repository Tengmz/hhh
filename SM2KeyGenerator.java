import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * SM2椭圆曲线密码算法密钥生成器
 * 基于国密标准GM/T 0003-2012实现
 */
public class SM2KeyGenerator {
    
    // SM2椭圆曲线参数 (基于推荐参数)
    // 素数p = 2^256 - 2^224 - 2^96 + 2^64 - 1
    private static final BigInteger P = new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16);
    
    // 椭圆曲线参数a
    private static final BigInteger A = new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16);
    
    // 椭圆曲线参数b
    private static final BigInteger B = new BigInteger("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16);
    
    // 基点G的x坐标
    private static final BigInteger GX = new BigInteger("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16);
    
    // 基点G的y坐标
    private static final BigInteger GY = new BigInteger("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16);
    
    // 基点G的阶n
    private static final BigInteger N = new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16);
    
    private final SecureRandom random;
    
    /**
     * 构造函数
     */
    public SM2KeyGenerator() {
        this.random = new SecureRandom();
    }
    
    /**
     * 构造函数（指定随机数生成器）
     * @param random 随机数生成器
     */
    public SM2KeyGenerator(SecureRandom random) {
        this.random = random;
    }
    
    /**
     * 生成SM2密钥对
     * @return SM2密钥对对象
     */
    public SM2KeyPair generateKeyPair() {
        // 1. 生成私钥d，1 ≤ d ≤ n-2
        BigInteger privateKey = generatePrivateKey();
        
        // 2. 计算公钥P = [d]G
        ECPoint publicKey = pointMultiply(privateKey, new ECPoint(GX, GY));
        
        return new SM2KeyPair(privateKey, publicKey);
    }
    
    /**
     * 生成私钥
     * @return 私钥（大整数）
     */
    private BigInteger generatePrivateKey() {
        BigInteger d;
        do {
            // 生成256位随机数
            byte[] randomBytes = new byte[32]; // 256 bits / 8 = 32 bytes
            random.nextBytes(randomBytes);
            d = new BigInteger(1, randomBytes);
        } while (d.equals(BigInteger.ZERO) || d.compareTo(N.subtract(BigInteger.ONE)) >= 0);
        
        return d;
    }
    
    /**
     * 椭圆曲线点乘运算 [k]P
     * @param k 标量
     * @param point 椭圆曲线上的点
     * @return 计算结果点
     */
    private ECPoint pointMultiply(BigInteger k, ECPoint point) {
        if (k.equals(BigInteger.ZERO)) {
            return ECPoint.INFINITY;
        }
        
        ECPoint result = ECPoint.INFINITY;
        ECPoint addend = point;
        
        while (k.compareTo(BigInteger.ZERO) > 0) {
            if (k.testBit(0)) {
                result = pointAdd(result, addend);
            }
            addend = pointDouble(addend);
            k = k.shiftRight(1);
        }
        
        return result;
    }
    
    /**
     * 椭圆曲线点加运算
     * @param p1 点1
     * @param p2 点2
     * @return 相加结果点
     */
    private ECPoint pointAdd(ECPoint p1, ECPoint p2) {
        if (p1.isInfinity()) {
            return p2;
        }
        if (p2.isInfinity()) {
            return p1;
        }
        
        if (p1.x.equals(p2.x)) {
            if (p1.y.equals(p2.y)) {
                return pointDouble(p1);
            } else {
                return ECPoint.INFINITY;
            }
        }
        
        // λ = (y2 - y1) / (x2 - x1)
        BigInteger numerator = p2.y.subtract(p1.y).mod(P);
        BigInteger denominator = p2.x.subtract(p1.x).mod(P);
        BigInteger lambda = numerator.multiply(denominator.modInverse(P)).mod(P);
        
        // x3 = λ² - x1 - x2
        BigInteger x3 = lambda.multiply(lambda).subtract(p1.x).subtract(p2.x).mod(P);
        
        // y3 = λ(x1 - x3) - y1
        BigInteger y3 = lambda.multiply(p1.x.subtract(x3)).subtract(p1.y).mod(P);
        
        return new ECPoint(x3, y3);
    }
    
    /**
     * 椭圆曲线点倍运算
     * @param point 输入点
     * @return 倍点结果
     */
    private ECPoint pointDouble(ECPoint point) {
        if (point.isInfinity()) {
            return ECPoint.INFINITY;
        }
        
        // λ = (3x² + a) / (2y)
        BigInteger numerator = point.x.multiply(point.x).multiply(BigInteger.valueOf(3)).add(A).mod(P);
        BigInteger denominator = point.y.multiply(BigInteger.valueOf(2)).mod(P);
        BigInteger lambda = numerator.multiply(denominator.modInverse(P)).mod(P);
        
        // x3 = λ² - 2x
        BigInteger x3 = lambda.multiply(lambda).subtract(point.x.multiply(BigInteger.valueOf(2))).mod(P);
        
        // y3 = λ(x - x3) - y
        BigInteger y3 = lambda.multiply(point.x.subtract(x3)).subtract(point.y).mod(P);
        
        return new ECPoint(x3, y3);
    }
    
    /**
     * 椭圆曲线上的点
     */
    public static class ECPoint {
        public static final ECPoint INFINITY = new ECPoint(null, null);
        
        public final BigInteger x;
        public final BigInteger y;
        
        public ECPoint(BigInteger x, BigInteger y) {
            this.x = x;
            this.y = y;
        }
        
        public boolean isInfinity() {
            return x == null && y == null;
        }
        
        @Override
        public String toString() {
            if (isInfinity()) {
                return "INFINITY";
            }
            return "(" + x.toString(16).toUpperCase() + ", " + y.toString(16).toUpperCase() + ")";
        }
        
        @Override
        public boolean equals(Object obj) {
            if (this == obj) return true;
            if (obj == null || getClass() != obj.getClass()) return false;
            
            ECPoint ecPoint = (ECPoint) obj;
            
            if (isInfinity() && ecPoint.isInfinity()) return true;
            if (isInfinity() || ecPoint.isInfinity()) return false;
            
            return x.equals(ecPoint.x) && y.equals(ecPoint.y);
        }
    }
    
    /**
     * SM2密钥对
     */
    public static class SM2KeyPair {
        private final BigInteger privateKey;
        private final ECPoint publicKey;
        
        public SM2KeyPair(BigInteger privateKey, ECPoint publicKey) {
            this.privateKey = privateKey;
            this.publicKey = publicKey;
        }
        
        /**
         * 获取私钥
         * @return 私钥
         */
        public BigInteger getPrivateKey() {
            return privateKey;
        }
        
        /**
         * 获取公钥
         * @return 公钥点
         */
        public ECPoint getPublicKey() {
            return publicKey;
        }
        
        /**
         * 获取私钥的十六进制字符串表示
         * @return 私钥十六进制字符串
         */
        public String getPrivateKeyHex() {
            String hex = privateKey.toString(16).toUpperCase();
            // 补齐到64位（32字节）
            while (hex.length() < 64) {
                hex = "0" + hex;
            }
            return hex;
        }
        
        /**
         * 获取公钥的十六进制字符串表示（非压缩格式）
         * @return 公钥十六进制字符串
         */
        public String getPublicKeyHex() {
            if (publicKey.isInfinity()) {
                return "00";
            }
            
            String xHex = publicKey.x.toString(16).toUpperCase();
            String yHex = publicKey.y.toString(16).toUpperCase();
            
            // 补齐到64位
            while (xHex.length() < 64) {
                xHex = "0" + xHex;
            }
            while (yHex.length() < 64) {
                yHex = "0" + yHex;
            }
            
            // 04表示非压缩格式
            return "04" + xHex + yHex;
        }
        
        @Override
        public String toString() {
            return "SM2KeyPair{\n" +
                   "  privateKey=" + getPrivateKeyHex() + "\n" +
                   "  publicKey=" + getPublicKeyHex() + "\n" +
                   "}";
        }
    }
}