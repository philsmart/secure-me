package uk.ac.cardiff.nsa.security.token;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Created by philsmart on 20/03/2017.
 */
public class SharedKey {

    public static String sharedKey = "27CAEC6DE81728AB3FE5247C6F34E";

    public static String sharedKey2 = "27CAEC6DE81728AB3FE5247C6F34P";


    public static PublicKey rsaPubKey;

    public static PrivateKey rsaPrivateKey;

    static {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair kp = keyGen.genKeyPair();
            byte[] publicKey = kp.getPublic().getEncoded();
            rsaPubKey = kp.getPublic();
            rsaPrivateKey = kp.getPrivate();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    /**
     * THE BELOW ARE NOT USED ----
     */


    public static String rsaPublicKey2048 = "AAAAB3NzaC1yc2EAAAADAQABAAABAQC105/SNvb3+9m0/" +
            "tDph7ABxVusSyxylKccxjEyzuzbvein3bSRu9axRYOU+Z1+bx1XNkFXoTT0gyhd13pn9Ia4yf+2" +
            "2Tm7S21QBrpDGRq0n9UMrd61HXY8ek8tAbDwsV7KxRNCdyYx2vjjw89FOn9vXBdLfIrdsvuAQuU" +
            "xTV2IomqOzuvKasoRSa7yY9A0mMzNhWZBhrvJIc8T25h/Ac+otH95Eip5kS1avZRmtp5oDDi2qe" +
            "/2514rN7BpUe8E7cVPGI9JD5BfhHF3vYYW+uZ31pDrP9+3+v2mQ8SJeEnN85A7ouQ8cBbSmcfHa" +
            "0DLoMHwvZFgWNlxDQ+46Te/0pNT";

    public static String rsaPrivateKey2048 = "MIIEowIBAAKCAQEAtdOf0jb29/vZtP7Q6YewAcVbrEsscpSnHMYxMs7s273op920" +
            "kbvWsUWDlPmdfm8dVzZBV6E09IMoXdd6Z/SGuMn/ttk5u0ttUAa6QxkatJ/VDK3e" +
            "tR12PHpPLQGw8LFeysUTQncmMdr448PPRTp/b1wXS3yK3bL7gELlMU1diKJqjs7r" +
            "ymrKEUmu8mPQNJjMzYVmQYa7ySHPE9uYfwHPqLR/eRIqeZEtWr2UZraeaAw4tqnv" +
            "9udeKzewaVHvBO3FTxiPSQ+QX4Rxd72GFvrmd9aQ6z/ft/r9pkPEiXhJzfOQO6Lk" +
            "PHAW0pnHx2tAy6DB8L2RYFjZcQ0PuOk3v9KTUwIDAQABAoIBAATUi2FdPnBWC3GI" +
            "d2pMxXs2j/niwVqF4m6cQUBVSOuJfv2+oQZiFBD/hMBXZTyvnPrtIQ0/5hU8yry7" +
            "da//SfjsvNNRr/vuxAelNhuENjZoLJO6prjvAG4Y3bOXYOjz/U2rsJhKbARVCdmb" +
            "IQ14wVvm+WNy+olrMM02ebo2kO6JPopQ/U2pYnYMWf48SvJab3hZwiZZOdCZq5ag" +
            "JJjM7EqTChdnlI4cp3e7GugFRjX/iWcW0TBtcJhV0Y9nkUjv9NzO+lYU4Fbba8Z+" +
            "UJAE770Tq4GrEhjmz91xzV+Hf1yGVU5sUIaFh9i8XeWTTJvXEA3MQrdDbnRR8oly" +
            "X8IuIUkCgYEA5Clw2pWoaSsM9Qrf377dyHMgW/TM9pSg3nDDgx2Dx4wddbG680Yw" +
            "zpKgGoA/MFQO5e9kJ31Qg2ot9lFT7Wx/tNRp70UqERAyspolqEGl4eZ3sxqji3kk" +
            "Y5g0lQdKG9aRcgf0zdfY+UT+TG2wWPYjfYZ7BiEZQsPpdQIpbw7F7t8CgYEAzALr" +
            "IucFHhQkT6dc8kbEmcd3WM3rl/EWTo2qW4c0pO6qDkWNCfT/+PjZTVP8eAlwi5dz" +
            "nogzc2qp3vfrFV8x9CJ6/fdd3N4h3Ss31wUxw20jYDD8PCJ4+GsJ6zt45JbSVfdy" +
            "1k6Gl7SwanL+E6HHZFf7AYnsjSe2hTASZC4yzg0CgYEAu0lZHdRjXZC9HhhDFML0" +
            "AqqeEV2tMWtncbBWjLYZih91vzqZH0Cqp6asTZSgSed2I0CSkefHw1fRSrQPlIDP" +
            "g3wpSQMZONB3DSyDZM4egIRSFW70eHSEbkxuPTaymo9S7KujQ6S+sj70D4CqlRvW" +
            "nh9ZtPpOZgOzCx0vLb6OszkCgYA/F7f4d1HR15DTQYMxOkma9WEniaeOufSYHp/M" +
            "5qeVSmo1N7VCmw5+xRcPHyY5SVIRGamcIasnypj2Z93AIkykn/VBjbrtj5URfUgr" +
            "q2OUeLA0E3IudsrKqO/MW/wrVal/BKPzOx3M1QiqIx4InEO5+Kub8jfB/8ImtpM5" +
            "gEAeEQKBgD3NJa3SKlSNuj6ZNjcKJf7c8fg/m8iqp3r79CdZeG8C5eyQtttPWxoP" +
            "NcAy7cSPH1D9WalbATef2RFxXwj6P4eUN4q9DGUcIMU6vIKmHlx4VzZssPV3hmVQ" +
            "9SWStw6Tj/kg+TaiBNyjWVpuwCdNGHZ6ZTe2jE249FB9hv0yzr/e";



}
