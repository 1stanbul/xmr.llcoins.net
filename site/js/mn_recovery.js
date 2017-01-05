//mnemonic recovery by JollyMort
//lazy "just make it work" style, not optimized, completes within 'reasonable' time for 2 missing words
//todo:
// - support missing checksum, too
// - user-friendliness
// when? probably never.

function mn_guess(str, wordset_name, target_address) {
    'use strict';
    wordset_name = wordset_name || mn_default_wordset;
    var wordset = mn_words[wordset_name];
    var out = '';
    var n = wordset.words.length;
    var wlist = str.split(' ');
    var checksum_word = '';
	var netbyte = pubAddrNetByte.value;
    //if (wlist.length < 12) throw "You've entered too few words, please try again";
    if ((wordset.prefix_len === 0 && (wlist.length % 3 !== 0)) ||
        (wordset.prefix_len > 0 && (wlist.length % 3 === 2))) throw "You've entered too few words, please try again";
    if (wordset.prefix_len > 0 && (wlist.length % 3 === 0)) throw "You seem to be missing the last word in your private key, please try again";
    if (wordset.prefix_len > 0) {
        // Pop checksum from mnemonic
        checksum_word = wlist.pop();
    }
	// Find occurences of "<missing>"
	var mn_missing = [];
	for (var i = 0; i < wlist.length; i+= 1)
	{
		if (wlist[i] == "<missing>")
		{			
			mn_missing.push(i);
		}
	}
	
	if (mn_missing.length > 0 && mn_missing.length < 3)
	{
		console.log("Combinations: " + Math.pow(wordset.words.length,(mn_missing.length)));
		var candidates=0;
		//check for maximum 2 missing words;
		for(var i = 0; i < Math.pow(wordset.words.length,(mn_missing.length)); i++)
		{
			//loop all combinations
			if(i % 1000 == 0)
			{
				document.getElementById('mnemonic').innerHTML = i + "/" + Math.pow(wordset.words.length,(mn_missing.length));
			}
			for (var j = 0; j < mn_missing.length; j++)
			{
				wlist[mn_missing[j]] = wordset.words[parseInt((i % Math.pow(wordset.words.length,(j+1))) / Math.pow(wordset.words.length,j))];
			}
			if (wordset.prefix_len > 0) {
				var index = mn_get_checksum_index(wlist, wordset.prefix_len);
				var expected_checksum_word = wlist[index];
				if (expected_checksum_word.slice(0, wordset.prefix_len) == checksum_word.slice(0, wordset.prefix_len)) {		
					console.log("i=" + i + " Candidate: " + wlist);
					candidates+=1;
					// Decode mnemonic
					out = "";
					for (var k = 0; k < wlist.length; k += 3) { /////// heres
						var w1, w2, w3;
						if (wordset.prefix_len === 0) {
							w1 = wordset.words.indexOf(wlist[k]);
							w2 = wordset.words.indexOf(wlist[k + 1]);
							w3 = wordset.words.indexOf(wlist[k + 2]);
						} else {
							w1 = wordset.trunc_words.indexOf(wlist[k].slice(0, wordset.prefix_len));
							w2 = wordset.trunc_words.indexOf(wlist[k + 1].slice(0, wordset.prefix_len));
							w3 = wordset.trunc_words.indexOf(wlist[k + 2].slice(0, wordset.prefix_len));
						}
						if (w1 === -1 || w2 === -1 || w3 === -1) {
							throw "invalid word in mnemonic";
						}
						var x = w1 + n * (((n - w1) + w2) % n) + n * n * (((n - w2) + w3) % n);
						if (x % n != w1) throw 'Something went wrong when decoding your private key, please try again';
						out += mn_swap_endian_4byte(('0000000' + x.toString(16)).slice(-8));
					}	
					// Calculate Address					
					if (wlist.length == 24)
					{
						//normal
							var privSk = sc_reduce32(out);
							var privVk = sc_reduce32(cn_fast_hash(privSk));
					}
					else
					{
						//mymonero
							var privSk = sc_reduce32(cn_fast_hash(out));
							var privVk = sc_reduce32(cn_fast_hash(cn_fast_hash(out)));
					}
					
					var pubSk = sec_key_to_pub(privSk);
					var pubVk = sec_key_to_pub(privVk);
					var address = toPublicAddr(netbyte, pubSk, pubVk);
					if (address == target_address)
					{
						console.log("It's a match! Address=" + address);
						mnemonic.value = mn_encode(out);
						hexSeed.value = out;
						privSpend.value = privSk;
						pubSpend.value = pubSk;
						privView.value = privVk;
						pubView.value = pubVk;
						pubAddr.value = address;
						return 0;
					}
					else
					{ 
						console.log("Candidate not matching: " + i);
					}
					
				}
			}
			//return out;
		}
		console.log("Candidates: " + candidates);
	}
	else throw "nothing to guess or too many unknowns";
}

function allRandomMm(){
    var netbyte = pubAddrNetByte.value;
    var hs = rand_16();
    var hs32 = cn_fast_hash(hs);
    var i = 0;
    while (hs32 !== sc_reduce32(hs32)){
        hs = rand_16();
        hs32 = cn_fast_hash(hs);
        i++
    }
    console.log("Found simplewallet-compatible MyMonero seed after " + i + " attempts (~16 expected).");
    if (netbyte === "11"){
        //var hs = rand_16();
        var mn = mn_encode(hs, mnDictTag.value);
        var privSk = sc_reduce32(hs32);
        var pubSk = sec_key_to_pub(privSk);
        var privVk = sc_reduce32(cn_fast_hash(pubSk));
        var pubVk = sec_key_to_pub(privVk);
    } else {
        //var hs = rand_16();
        var mn = mn_encode(hs, mnDictTag.value);
        var privSk = sc_reduce32(hs32);
        var privVk = sc_reduce32(cn_fast_hash(hs32));
        var pubSk = sec_key_to_pub(privSk);
        var pubVk = sec_key_to_pub(privVk);
        if (netbyte === "13"){
            var pID = rand_32().slice(0,16);
        }
    }
    var address = toPublicAddr(netbyte, pubSk, pubVk, pID);
    if (!pID){
        paymentID.value = "";
    } else {
        paymentID.value = pID;
    }
    mnemonic.value = mn;
    hexSeed.value = hs;
    privSpend.value = privSk;
    pubSpend.value = pubSk;
    privView.value = privVk;
    pubView.value = pubVk;
    pubAddr.value = address;
}