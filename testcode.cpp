#include "openfhe.h"
#include "testcode.h"
#include "algorithms.h"

using namespace lbcrypto;
using namespace std;

namespace ckkssample {


    void sqTest() {

        uint32_t multDepth = 5;
        uint32_t batchSize = 1 << 14;

        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetMultiplicativeDepth(multDepth);
        parameters.SetScalingModSize(scaleModSize);
        parameters.SetRingDim(batchSize << 1);
        parameters.SetBatchSize(batchSize);
        
        CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);

        auto keys = cc->KeyGen();
        cc->EvalMultKeyGen(keys.secretKey);

        std::cout << "!!!!!!!!!!!!!!! Test !!!!!!!!!!!!!!!" << std::endl;

        // Inputs
        std::vector<double> x1(batchSize);
        Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1);

        for(usint i=0;i<batchSize;i++)x1[i]=1;

        // Encrypt the encoded vectors
        ptxt1 = cc->MakeCKKSPackedPlaintext(x1);
        auto c1 = cc->Encrypt(keys.publicKey, ptxt1);
        Plaintext result;

        auto c2 = EvalSq(c1, 3);

        cc->Decrypt(keys.secretKey, c2, &result);
    } 

   

    


}
