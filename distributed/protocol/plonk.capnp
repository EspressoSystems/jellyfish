@0x9663f4dd604afa35;

struct Chunk {
    data @0: Data;
    hash @1: UInt64;
}

interface PlonkWorker {
    keyGenPrepare                   @0 ();
    keyGenSetCk                     @1 (data: Data, hash: UInt64);

    keyGenCommit                    @2 (seed: Data) -> (c_q: Data, c_s: Data);

    proveInit                       @3 ();

    proveRound1                     @4 () -> (c: Data);

    proveRound2Compute              @5 (beta: Data, gamma: Data);
    proveRound2Exchange             @6 ();
    proveRound2Commit               @7 () -> (c: Data);
    placeholder7                    @8 ();
    placeholder8                    @9 ();

    proveRound3Prepare                          @10 (alpha: Data);
    proveRound3ComputeTPart1Type1               @11 ();
    proveRound3ExchangeTPart1Type1              @12 ();
    proveRound3ExchangeW1                       @13 ();
    proveRound3ComputeAndExchangeW3             @14 ();
    proveRound3ComputeAndExchangeTPart1Type3    @15 ();
    proveRound3ComputeAndExchangeTPart2         @16 ();
    proveRound3ComputeAndExchangeTPart1Type2    @17 ();
    proveRound3ComputeAndExchangeTPart3         @18 ();
    proveRound3Commit                           @19 () -> (c: Data);

    proveRound4EvaluateW                        @20 (zeta: Data) -> (w: Data);
    proveRound4EvaluateSigmaOrZ                 @21 () -> (sigma_or_z: Data);

    placeholder15                   @22 ();
    placeholder16                   @23 ();
    placeholder17                   @24 ();
    placeholder18                   @25 ();
    placeholder19                   @26 ();
    placeholder20                   @27 ();
    placeholder21                   @28 ();
    placeholder22                   @29 ();

    proveRound5Prepare              @30 (v: Data, s1: Data, s2: Data);
    proveRound5Exchange             @31 ();
    proveRound5Commit               @32 () -> (c_t: Data, c_z: Data);

    placeholder23                   @33 ();
    placeholder24                   @34 ();
    placeholder25                   @35 ();
    placeholder26                   @36 ();
    placeholder27                   @37 ();
    placeholder28                   @38 ();
    proveRound2UpdateZ              @39 (z: List(Chunk));

    proveRound3UpdateW1Product      @40 (w1: List(Chunk));
    proveRound3UpdateW3Product      @41 (w3: List(Chunk));
    proveRound3UpdateT              @42 (offset: UInt64, t: Chunk);
    proveRound3GetW1Product         @43 (start: UInt64, end: UInt64) -> (w1: Chunk);
    proveRound3GetW2Product         @44 (start: UInt64, end: UInt64) -> (w2: Chunk);
    proveRound3GetW3Product         @45 (start: UInt64, end: UInt64) -> (w3: Chunk);

    proveRound5Update              @46 (w: Data, t: List(Chunk));
}
