import { testCrypto } from "./helper";
import { ITestParams, ITestPlatform, ITestVectorsExclude } from "./types";
import * as Vectors from "./vectors";

export class WebcryptoTest {
  /**
   * Adds non default check
   * @param func
   */
  public static add(crypto: Crypto, param: ITestParams, platform?: Partial<ITestPlatform>) {
    testCrypto(crypto, param, platform);
  }

  /**
   * Default check
   * @param crypto
   * @param vectors
   */
  public static check(crypto: Crypto, vectors?: ITestParams[] | ITestVectorsExclude, platform?: Partial<ITestPlatform>) {
    if (Array.isArray(vectors)) {
      vectors.forEach((element) => {
        testCrypto(crypto, element, platform);
      });
    } else {
      for (const key in Vectors) {
        if (!vectors?.[key]) {
          testCrypto(crypto, (Vectors as any)[key], platform);
        }
      }
    }
  }
}
