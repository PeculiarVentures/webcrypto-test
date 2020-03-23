import { ITestParams, ITestVectorsExclude } from "./types";
export declare class WebcryptoTest {
    /**
     * Adds non default check
     * @param func
     */
    static add(crypto: Crypto, param: ITestParams): void;
    /**
     * Default check
     * @param crypto
     * @param vectors
     */
    static check(crypto: Crypto, vectors?: ITestParams[] | ITestVectorsExclude): void;
}
