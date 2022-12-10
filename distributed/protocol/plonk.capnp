@0x9663f4dd604afa35;

struct MsmWorkload {
    start @0 : UInt64;
    end @1 : UInt64;
}

struct FftWorkload {
    rowStart @0 : UInt64;
    rowEnd @1 : UInt64;
    colStart @2 : UInt64;
    colEnd @3 : UInt64;
}

interface PlonkSlave {
    init @0 (bases :List(Data), domainSize :UInt64, quotDomainSize :UInt64);
    varMsm @1 (workload: MsmWorkload, scalars :List(Data)) -> (result: Data);

    fftInit @2 (id: UInt64, workloads: List(FftWorkload), is_quot: Bool, is_inv: Bool, is_coset: Bool);
    fft1 @3 (id: UInt64, i: UInt64, v: List(Data));
    fft2Prepare @4 (id: UInt64);
    fft2 @5 (id: UInt64) -> (v: List(Data));

    round1 @6 (w: List(Data)) -> (c: Data);

    round3Step1AH @7 (q_a: List(Data), q_h: List(Data)) -> (v: List(Data));
    round3Step1O @8 (q_o: List(Data)) -> (v: List(Data));
    round3Step2Init @9 ();
    round3Step2MRetrieve @10 (q_m: List(Data)) -> (v: List(Data));
    round3Step2ERetrieve @11 (q_e: List(Data)) -> (v: List(Data));
    round3Step3 @12 (beta: Data, gamma: Data, k: Data) -> (v: List(Data));
    round3Step4 @13 (sigma: List(Data)) -> (v: List(Data));
    round3Step5 @14 (t: List(Data)) -> (c: Data);

    round4 @15 (zeta: Data) -> (v1: Data, v2: Data);

    round5Step1 @16 () -> (v1: List(Data), v2: Data, v3: Data);
    round5Step2Init @17 ();
    round5Step2MRetrieve @18 () -> (v: Data);
    round5Step2ERetrieve @19 () -> (v: Data);
    # round5Step2MRetrieve @18 () -> (v: List(Data));
    # round5Step2ERetrieve @19 () -> (v: List(Data));
    round5Step3 @20 (v: Data) -> (v: List(Data));
}

interface PlonkPeer {
    fftExchange @0 (id: UInt64, from: UInt64, v: List(Data));

    round3Step2MExchange @1 (w: List(Data));
    round3Step2EExchange @2 (w: List(Data));
    round5Step2MExchange @3 (w: Data);
    round5Step2EExchange @4 (w: Data);
}
