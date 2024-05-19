#include "openfhe.h"
#include "utils.h"
#include "algorithms.h"
#include <iostream>
#include <vector>

using namespace lbcrypto;
using namespace std;

namespace ckkssample {


Ciphertext<DCRTPoly> EvalSq(const Ciphertext<DCRTPoly> ciphertext, const usint num) {
    Ciphertext<DCRTPoly> result = ciphertext->Clone();
    Ciphertext<DCRTPoly> tmp; 
	
    const auto cc = ciphertext->GetCryptoContext();

	for(usint s=0 ; s < num ; s++){
		result = cc->EvalMult(result, result);
        cc->ModReduceInPlace(result);
	}

    return result;
}

}