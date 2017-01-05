//mnemonic recovery by JollyMort
//lazy "just make it work" style, not optimized, completes within 'reasonable' time for 2 missing words
//todo:
// - support missing checksum, too
// - user-friendliness
// when? probably never.

function mnRecover()
{
	tgtAddr = document.getElementById('tgtAddr');
	if (tgtAddr.value.length == 95)
	{
		mn_guess(mnemonic.value, mnDictTag.value, tgtAddr.value);
	}
}

function mn_guess(str, wordset_name, target_address) {
    'use strict';
    wordset_name = wordset_name || mn_default_wordset;
    var wordset = mn_words[wordset_name];
    var out = '';
    var n = wordset.words.length;
    var wlist = str.split(' ');
    var checksum_word = '';
	var netbyte = pubAddrNetByte.value;
	var privSk;
	var privVk;
	var pubSk;
	var pubVk;
	var address;	
	var index;
	var expected_checksum_word;
	var w1, w2, w3;
	var x;
	var i, j, k;
	
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
		for(i = 0; i < Math.pow(wordset.words.length,(mn_missing.length)); i++)
		{
			//loop all combinations
			if(i % 10000 == 0)
			{
				console.clear();
			}
			for (j = 0; j < mn_missing.length; j++)
			{
				wlist[mn_missing[j]] = wordset.words[parseInt((i % Math.pow(wordset.words.length,(j+1))) / Math.pow(wordset.words.length,j))];
			}
			if (wordset.prefix_len > 0) {
				index = mn_get_checksum_index(wlist, wordset.prefix_len);
				expected_checksum_word = wlist[index];
				if (expected_checksum_word.slice(0, wordset.prefix_len) == checksum_word.slice(0, wordset.prefix_len)) {		
					console.log("i=" + i + " Candidate: " + wlist);
					candidates+=1;
					// Decode mnemonic
					out = "";
					for (k = 0; k < wlist.length; k += 3) { /////// heres
						// var w1, w2, w3;
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
						x = w1 + n * (((n - w1) + w2) % n) + n * n * (((n - w2) + w3) % n);
						if (x % n != w1) throw 'Something went wrong when decoding your private key, please try again';
						out += mn_swap_endian_4byte(('0000000' + x.toString(16)).slice(-8));
					}	
					// Calculate Address					
					if (wlist.length == 24)
					{
						//normal
							privSk = sc_reduce32(out);
							privVk = sc_reduce32(cn_fast_hash(privSk));
					}
					else
					{
						//mymonero
							privSk = sc_reduce32(cn_fast_hash(out));
							privVk = sc_reduce32(cn_fast_hash(cn_fast_hash(out)));
					}
					
					pubSk = sec_key_to_pub(privSk);
					pubVk = sec_key_to_pub(privVk);
					address = toPublicAddr(netbyte, pubSk, pubVk);
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
					privSk = null;
					privVk = null;
					pubSk = null;
					pubVk = null;
					address = null;
					
				}
			}
			//return out;
		}
		console.log("Candidates: " + candidates);
	}
	else throw "nothing to guess or too many unknowns";
}
