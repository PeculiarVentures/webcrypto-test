export interface ITestAction {
    name?: string;
    only?: boolean;
    skip?: boolean;
    error?: any;
}
export interface ITestVectorsExclude {
    [name: string]: boolean | undefined;
    AES128CBC?: boolean;
    AES192CBC?: boolean;
    AES256CBC?: boolean;
    AES128CMAC?: boolean;
    AES192CMAC?: boolean;
    AES128CTR?: boolean;
    AES192CTR?: boolean;
    AES256CTR?: boolean;
    AES128ECB?: boolean;
    AES192ECB?: boolean;
    AES256ECB?: boolean;
    AES128GCM?: boolean;
    AES192GCM?: boolean;
    AES256GCM?: boolean;
    AES128KW?: boolean;
    AES192KW?: boolean;
    AES256KW?: boolean;
    DESCBC?: boolean;
    DESEDE3CBC?: boolean;
    RSAESPKCS1?: boolean;
    RSASSAPKCS1?: boolean;
    RSAOAEP?: boolean;
    RSAPSS?: boolean;
    ECDSA?: boolean;
    ECDH?: boolean;
    HKDF?: boolean;
    HMAC?: boolean;
    PBKDF2?: boolean;
    SHA?: boolean;
}
export interface ITestGenerateKeyAction extends ITestAction {
    algorithm: Algorithm;
    extractable: boolean;
    keyUsages: KeyUsage[];
}
export interface IImportKeyParams {
    format: KeyFormat;
    data: JsonWebKey | BufferSource;
    algorithm: AlgorithmIdentifier;
    extractable: boolean;
    keyUsages: KeyUsage[];
}
export interface IImportKeyPairParams {
    privateKey: IImportKeyParams;
    publicKey: IImportKeyParams;
}
export interface ITestEncryptAction extends ITestAction {
    algorithm: Algorithm;
    data: BufferSource;
    encData: BufferSource;
    key: IImportKeyParams | IImportKeyPairParams;
}
export interface ITestSignAction extends ITestAction {
    algorithm: Algorithm;
    data: BufferSource;
    signature: BufferSource;
    key: IImportKeyParams | IImportKeyPairParams;
}
export interface ITestDeriveBitsAction extends ITestAction {
    algorithm: Algorithm;
    key: IImportKeyParams | IImportKeyPairParams;
    data: BufferSource;
    length: number;
}
export interface ITestDeriveKeyAction extends ITestAction {
    algorithm: Algorithm;
    key: IImportKeyParams | IImportKeyPairParams;
    derivedKeyType: Algorithm;
    keyUsages: KeyUsage[];
    format: KeyFormat;
    keyData: BufferSource | JsonWebKey;
}
export interface ITestWrapKeyAction extends ITestAction {
    key: IImportKeyParams | IImportKeyPairParams;
    algorithm: Algorithm;
    wKey: IImportKeyParams;
    wrappedKey?: BufferSource;
}
export interface ITestImportAction extends IImportKeyParams, ITestAction {
}
export interface ITestDigestAction extends ITestAction {
    algorithm: AlgorithmIdentifier;
    data: BufferSource;
    hash: BufferSource;
}
export interface ITestActions {
    generateKey?: ITestGenerateKeyAction[];
    encrypt?: ITestEncryptAction[];
    wrapKey?: ITestWrapKeyAction[];
    sign?: ITestSignAction[];
    import?: ITestImportAction[];
    deriveBits?: ITestDeriveBitsAction[];
    deriveKey?: ITestDeriveKeyAction[];
    digest?: ITestDigestAction[];
}
export interface ITestParams {
    name: string;
    only?: boolean;
    actions: ITestActions;
}
