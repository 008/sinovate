// Copyright (c) 2018-2019 SIN developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <sinovate/rpc/infinitynode.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <rpc/net.h>
#include <rpc/rawtransaction_util.h>
#include <core_io.h>


static RPCHelpMan infinitynode()
{
    return RPCHelpMan{"infinitynode",
                "\nGet detailed information about infinitynode and sinovate network\n",
                {
                    {"strCommand", RPCArg::Type::STR, RPCArg::Optional::NO, "The command"},
                    {"strFilter", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "The filter of command"},
                    {"strOption", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "The option of command"},
                },
                {
                    RPCResult{RPCResult::Type::NONE, "", ""},
                    RPCResult{RPCResult::Type::NUM, "", ""},
                    RPCResult{RPCResult::Type::STR, "", ""},
                    RPCResult{RPCResult::Type::BOOL, "", ""},
                    RPCResult{"keypair, checkkey command",
                        RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::STR_HEX, "PrivateKey", "The PrivateKey"},
                            {RPCResult::Type::STR_HEX, "PublicKey", "The PublicKey"},
                            {RPCResult::Type::STR_HEX, "DecodePublicKey", "DecodePublicKey"},
                            {RPCResult::Type::STR, "Address", "The Address"},
                            {RPCResult::Type::BOOL, "isCompressed", "isCompressed (true/false)"},
                        },
                    },
                    RPCResult{"mypeerinfo",
                        RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::STR, "MyPeerInfo", "The candidate of reward for BIG node"},
                        },
                    },
                    RPCResult{"build-stm",
                        RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::STR, "Height", "The candidate of reward for BIG node"},
                            {RPCResult::Type::STR, "Result", "The candidate of reward for MID node"},
                        },
                    },
                    RPCResult{"show-candidate command",
                        RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::STR, "CandidateBIG", "The candidate of reward for BIG node"},
                            {RPCResult::Type::STR, "CandidateMID", "The candidate of reward for MID node"},
                            {RPCResult::Type::STR, "CandidateLIL", "The candidate of reward for LIL node"},
                        },
                    },
                },
                RPCExamples{
                    "\nCreate a new Private/Public key\n"
                    + HelpExampleCli("infinitynode", "keypair")
                    + "\nCheck Private key\n"
                    + HelpExampleCli("infinitynode", "checkkey PRIVATEKEY")
                    + "\nInfinitynode: Get current block height\n"
                    + HelpExampleCli("infinitynode", "getrawblockcount")
                    + "\nInfinitynode: show peer info\n"
                    + HelpExampleCli("infinitynode", "mypeerinfo")
                    + "\nShow current statement of Infinitynode\n"
                    + HelpExampleCli("infinitynode", "show-stm")
                    + "\nShow current statement of Infinitynode at Height\n"
                    + HelpExampleCli("infinitynode", "show-stm-at")
                    + "\nShow the candidates for Height\n"
                    + HelpExampleCli("infinitynode", "show-candidate height")
                    + "\nShow informations about all infinitynodes of network.\n"
                    + HelpExampleCli("infinitynode", "show-infos")
                    + "\nShow metadata of all infinitynodes of network.\n"
                    + HelpExampleCli("infinitynode", "show-nonmatured")
                    + "\nShow metadata of all infinitynodes in non matured map, waiting to be listed in final list.\n"
                    + HelpExampleCli("infinitynode", "show-metadata")
                    + "\nShow lockreward of network.\n"
                    + HelpExampleCli("infinitynode", "show-lockreward")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::string strCommand = request.params[0].get_str();
    std::string strError;

    UniValue obj(UniValue::VOBJ);

    if (strCommand == "keypair")
    {
        CKey secret;
        secret.MakeNewKey(true);
        CPubKey pubkey = secret.GetPubKey();
        assert(secret.VerifyPubKey(pubkey));

        std::string sBase64 = EncodeBase64(pubkey);
        std::vector<unsigned char> tx_data = DecodeBase64(sBase64.c_str());
        CPubKey decodePubKey(tx_data.begin(), tx_data.end());
        CTxDestination dest = GetDestinationForKey(decodePubKey, DEFAULT_ADDRESS_TYPE);

        obj.pushKV("PrivateKey", EncodeSecret(secret));
        obj.pushKV("PublicKey", sBase64);
        obj.pushKV("DecodePublicKey", decodePubKey.GetID().ToString());
        obj.pushKV("Address", EncodeDestination(dest));
        obj.pushKV("isCompressed", pubkey.IsCompressed());
        return obj;
    }

    if (strCommand == "checkkey")
    {
        const std::string strKey = request.params[1].get_str();
        CKey secret = DecodeSecret(strKey);
        if (!secret.IsValid()) throw JSONRPCError(RPC_INTERNAL_ERROR, "Not a valid key");

        CPubKey pubkey = secret.GetPubKey();
        assert(secret.VerifyPubKey(pubkey));

        std::string sBase64 = EncodeBase64(pubkey);
        std::vector<unsigned char> tx_data = DecodeBase64(sBase64.c_str());
        CPubKey decodePubKey(tx_data.begin(), tx_data.end());
        CTxDestination dest = GetDestinationForKey(decodePubKey, DEFAULT_ADDRESS_TYPE);

        obj.pushKV("PrivateKey", EncodeSecret(secret));
        obj.pushKV("PublicKey", sBase64);
        obj.pushKV("DecodePublicKey", decodePubKey.GetID().ToString());
        obj.pushKV("Address", EncodeDestination(dest));
        obj.pushKV("isCompressed", pubkey.IsCompressed());

        return obj;
    }

    if (strCommand == "getblockcount")
    {
        if (!fInfinityNode)
            throw JSONRPCError(RPC_INTERNAL_ERROR, "This is not an InfinityNode");

        return infinitynodePeer.getCacheHeightInf();
    }

    if (strCommand == "getrawblockcount")
    {
        if (!fInfinityNode)
            throw JSONRPCError(RPC_INTERNAL_ERROR, "This is not an InfinityNode");
        int ret = nRawBlockCount;
        return ret;
    }

    if (strCommand == "mypeerinfo")
    {
        if (!fInfinityNode)
            throw JSONRPCError(RPC_INTERNAL_ERROR, "This is not an InfinityNode");

        NodeContext& node = EnsureAnyNodeContext(request.context);
        CConnman& connman = EnsureConnman(node);

        UniValue infObj(UniValue::VOBJ);
        infinitynodePeer.ManageState(connman);
        infObj.pushKV("MyPeerInfo", infinitynodePeer.GetMyPeerInfo());
        return infObj;
    }

    if (strCommand == "build-stm-to")
    {
        if (request.params.size() != 2)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Correct usage is 'infinitynode build-stm-to \"nHeight\"'");

        const std::string strFilter = request.params[1].get_str();

        int nHeight = atoi(strFilter);
        int nLoop = 0;
        int begin = Params().GetConsensus().nInfinityNodeGenesisStatement;

	if (nHeight <= begin){
            infnodeman.calculStatementOnValidation(nHeight);
            nLoop++;
        } else {
            for(int i = begin; i < nHeight; i++){
                infnodeman.calculStatementOnValidation(i);
                nLoop++;
            }
        }
        obj.pushKV("Begin at", begin);
        obj.pushKV("End at", nHeight);
        obj.pushKV("End of operator", nLoop);
        return obj;
    }

    if (strCommand == "show-stm")
    {
        return infnodeman.getLastStatementString();
    }

    if (strCommand == "show-stm-at")
    {
        if (request.params.size() != 2)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Correct usage is 'infinitynode show-stm-at \"nHeight\"'");

        const std::string strFilter = request.params[1].get_str();

        int nHeight = atoi(strFilter);

        if (nHeight < Params().GetConsensus().nInfinityNodeGenesisStatement) {
            strError = strprintf("nHeight must be higher than the Genesis Statement height (%s)", Params().GetConsensus().nInfinityNodeGenesisStatement);
            throw JSONRPCError(RPC_INVALID_PARAMETER, strError);
        }

        std::map<int, int> mapBIG = infnodeman.getStatementMap(10);
        std::map<int, int> mapMID = infnodeman.getStatementMap(5);
        std::map<int, int> mapLIL = infnodeman.getStatementMap(1);

        std::map<int,int>::iterator itBIG, itMID, itLIL;

        itBIG = mapBIG.upper_bound(nHeight);
        itMID = mapMID.upper_bound(nHeight);
        itLIL = mapLIL.upper_bound(nHeight);

        if(nHeight == Params().GetConsensus().nInfinityNodeGenesisStatement){
            std::ostringstream streamInfo;
            streamInfo << " " << nHeight << " BIG:" <<
                               itBIG->first << "/" << itBIG->second << " " <<
                               " MID:" <<
                               itMID->first << "/" << itMID->second << " " <<
                               " LIL:" <<
                               itLIL->first << "/" << itLIL->second << " "
                               ;
            std::string strInfo = streamInfo.str();
            obj.pushKV("Statement at", strInfo);
        } else if (nHeight > Params().GetConsensus().nInfinityNodeGenesisStatement){
            std::map<int, int>::iterator itLastBIG = --itBIG;
            std::map<int, int>::iterator itLastMID = --itMID;
            std::map<int, int>::iterator itLastLIL = --itLIL;

            std::ostringstream streamInfo;
            streamInfo << " " << nHeight << " BIG:" <<
                               itLastBIG->first << "/" << itLastBIG->second << " " <<
                               " MID:" <<
                               itLastMID->first << "/" << itLastMID->second << " " <<
                               " LIL:" <<
                               itLastLIL->first << "/" << itLastLIL->second << " "
                               ;
            std::string strInfo = streamInfo.str();
            obj.pushKV("Statement at", strInfo);
        }

        return obj;
    }

    if (strCommand == "show-candidate")
    {
        if (request.params.size() != 2)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Correct usage is 'infinitynode show-candidate \"nHeight\"'");

        const std::string strFilter = request.params[1].get_str();

        int nextHeight = atoi(strFilter);

        if (nextHeight < Params().GetConsensus().nInfinityNodeGenesisStatement) {
            strError = strprintf("nHeight must be higher than the Genesis Statement height (%s)", Params().GetConsensus().nInfinityNodeGenesisStatement);
            throw JSONRPCError(RPC_INVALID_PARAMETER, strError);
        }

        CInfinitynode infBIG, infMID, infLIL;
        LOCK(infnodeman.cs);
        infnodeman.deterministicRewardAtHeight_V2(nextHeight, 10, infBIG);
        infnodeman.deterministicRewardAtHeight_V2(nextHeight, 5, infMID);
        infnodeman.deterministicRewardAtHeight_V2(nextHeight, 1, infLIL);

        obj.pushKV("CandidateBIG: ", infBIG.getCollateralAddress());
        obj.pushKV("CandidateMID: ", infMID.getCollateralAddress());
        obj.pushKV("CandidateLIL: ", infLIL.getCollateralAddress());

        return obj;
    }

    if (strCommand == "show-nonmatured")
    {
        std::map<COutPoint, CInfinitynode> mapInfinitynodes = infnodeman.GetFullInfinitynodeNonMaturedMap();
        for (auto& infpair : mapInfinitynodes) {
            std::string strOutpoint = infpair.first.ToStringFull();
            CInfinitynode inf = infpair.second;
            std::ostringstream streamInfo;
            streamInfo << std::setw(8) <<
                inf.getCollateralAddress() << " " <<
                inf.getHeight() << " " <<
                inf.getExpireHeight() << " " <<
                inf.getRoundBurnValue() << " " <<
                inf.getSINType() << " " <<
                inf.getMetaID();
            std::string strInfo = streamInfo.str();
            obj.pushKV(strOutpoint, strInfo);
        }
        return obj;
    }

    if (strCommand == "show-infos")
    {
        std::map<COutPoint, CInfinitynode> mapInfinitynodes = infnodeman.GetFullInfinitynodeMap();
        std::map<std::string, CMetadata> mapInfMetadata = infnodemeta.GetFullNodeMetadata();
        for (auto& infpair : mapInfinitynodes) {
            std::string strOutpoint = infpair.first.ToStringFull();
            CInfinitynode inf = infpair.second;
            CMetadata meta = mapInfMetadata[inf.getMetaID()];
            std::string nodeAddress = "NodeAddress";

            if (meta.getMetaPublicKey() != "") nodeAddress = meta.getMetaPublicKey();

                std::ostringstream streamInfo;
                streamInfo << std::setw(8) <<
                               inf.getCollateralAddress() << " " <<
                               inf.getHeight() << " " <<
                               inf.getExpireHeight() << " " <<
                               inf.getRoundBurnValue() << " " <<
                               inf.getSINType() << " " <<
                               inf.getBackupAddress() << " " <<
                               inf.getLastRewardHeight() << " " <<
                               inf.getRank() << " " << 
                               infnodeman.getLastStatementSize(inf.getSINType()) << " " <<
                               inf.getMetaID() << " " <<
                               nodeAddress << " " <<
                               meta.getService().ToString()
                               ;
                std::string strInfo = streamInfo.str();
                obj.pushKV(strOutpoint, strInfo);
        }
        return obj;
    }

    if (strCommand == "show-metadata")
    {
        std::map<std::string, CMetadata>  mapCopy = infnodemeta.GetFullNodeMetadata();
        obj.pushKV("Metadata", (int)mapCopy.size());
        for (auto& infpair : mapCopy) {
            std::ostringstream streamInfo;
            std::vector<unsigned char> tx_data = DecodeBase64(infpair.second.getMetaPublicKey().c_str());

                CPubKey pubKey(tx_data.begin(), tx_data.end());
                CTxDestination nodeDest = GetDestinationForKey(pubKey, OutputType::LEGACY);

                streamInfo << std::setw(8) <<
                               infpair.second.getMetaPublicKey() << " " <<
                               infpair.second.getService().ToString() << " " <<
                               infpair.second.getMetadataHeight() << " " <<
                               EncodeDestination(nodeDest)
                ;
                std::string strInfo = streamInfo.str();

            UniValue metaHisto(UniValue::VARR);
            for(auto& v : infpair.second.getHistory()){
                 std::ostringstream vHistoMeta;
                 std::vector<unsigned char> tx_data_h = DecodeBase64(v.pubkeyHisto.c_str());

                 CPubKey pubKey_h(tx_data_h.begin(), tx_data_h.end());
                 CTxDestination nodeDest_h = GetDestinationForKey(pubKey_h, OutputType::LEGACY);

                 vHistoMeta << std::setw(4) <<
                     v.nHeightHisto  << " " <<
                     v.pubkeyHisto << " " <<
                     v.serviceHisto.ToString() << " " <<
                     EncodeDestination(nodeDest_h)
                     ;
                 std::string strHistoMeta = vHistoMeta.str();
                 metaHisto.push_back(strHistoMeta);
            }
            obj.pushKV(infpair.first, strInfo);
            std::string metaHistStr = strprintf("History %s", infpair.first);
            obj.pushKV(metaHistStr, metaHisto);
        }
        return obj;
    }

    if (strCommand == "show-lockreward")
    {
        NodeContext& node = EnsureAnyNodeContext(request.context);
        ChainstateManager& chainman = EnsureAnyChainman(request.context);
        CBlockIndex* pindex = NULL;
        {
            LOCK(cs_main);
            pindex = chainman.ActiveChain().Tip();
        }

        int nBlockNumber = pindex->nHeight - 55 * 10;

        std::vector<CLockRewardExtractInfo> vecLockRewardRet;
        infnodelrinfo.getLRInfoFromHeight(nBlockNumber, vecLockRewardRet);

        obj.pushKV("Result", (int)vecLockRewardRet.size());
        obj.pushKV("Current height", pindex->nHeight);
        int i=0;
        for (auto& v : vecLockRewardRet) {
                std::ostringstream streamInfo;
                CTxDestination address;
                bool fValidAddress = ExtractDestination(v.scriptPubKey, address);

                std::string owner = "Unknow";
                if(fValidAddress) owner = EncodeDestination(address);

                streamInfo << std::setw(1) <<
                               v.nSINtype << " " <<
                               owner  << " " <<
                               v.sLRInfo;
                std::string strInfo = streamInfo.str();
                obj.pushKV(strprintf("%d-%d",v.nBlockHeight, i), strInfo);
            i++;
        }
        return obj;
    }

    std::string strInfo = "Unknown command";
    obj.pushKV("Status:", strInfo);

    return obj;
},
    };
}

/**
 * @xtdevcoin
 * this function help user burn correctly their funds to run infinity node
 */
static RPCHelpMan infinitynodeburnfund()
{
    return RPCHelpMan{"infinitynodeburnfund",
                "\nBurn funds to create Infinitynode.\n"
                "\nReturns JSON info or Null.\n",
                {
                    {"nodeowneraddress", RPCArg::Type::STR, RPCArg::Optional::NO, "Address of owner (will receive the reward)."},
                    {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "The amount in " + CURRENCY_UNIT + " to create Node (Example: 100000). "},
                    {"backupaddress", RPCArg::Type::STR, RPCArg::Optional::NO, "backup of owner address"},
                },
                RPCResult{
                        RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::STR, "BURNADDRESS", "The BURNADDRESS of sinovate network"},
                            {RPCResult::Type::STR_HEX, "BURNPUBLICKEY", "The public key of owner"},
                            {RPCResult::Type::STR_HEX, "BURNSCRIPT", "The script of burn"},
                            {RPCResult::Type::STR_HEX, "BURNTX", "The transaction id"},
                            {RPCResult::Type::STR, "OWNERADDRESS", "The address of owner from which coins are burned and will receive the reward."},
                            {RPCResult::Type::STR, "BACKUPADDRESS", "The BACKUPADDRESS of owner (use in next feature)"},
                        },
                },
                RPCExamples{
                    "\nBurn 1 Milion SIN coins to create BIG Infinitynode\n"
                    + HelpExampleCli("infinitynodeburnfund", "NodeOwnerAddress 1000000 SINBackupAddress")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CWallet* const pwallet = wallet.get();

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    // Grab locks here as BlockUntilSyncedToCurrentChain() handles them on its own, but we need them for most other funcs
    LOCK2(pwallet->cs_wallet, cs_main);

    // SIN default format is LEGACY, so DecodeDestination is PKHash
    const std::string address = request.params[0].get_str();
    CTxDestination NodeOwnerAddress = DecodeDestination(address);
    if (!IsValidDestination(NodeOwnerAddress)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Sinovate address: ") + address);
    }
    CScript scriptPubKeyOwners = GetScriptForDestination(NodeOwnerAddress);

    CAmount nAmount = AmountFromValue(request.params[1]);
    if (nAmount != Params().GetConsensus().nMasternodeBurnSINNODE_1 * COIN &&
        nAmount != Params().GetConsensus().nMasternodeBurnSINNODE_5 * COIN &&
        nAmount != Params().GetConsensus().nMasternodeBurnSINNODE_10 * COIN)
    {
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount to burn and run an InfinityNode");
    }

    const std::string addressbk = request.params[2].get_str();
    CTxDestination BKaddress = DecodeDestination(addressbk);
    if (!IsValidDestination(BKaddress))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid SIN address as SINBackupAddress");

    std::string strError;
    int nMinDepth = 1;
    int nMaxDepth = 9999999;
    CAmount nMinimumAmount = 0;
    CAmount nMaximumAmount = MAX_MONEY;
    CAmount nMinimumSumAmount = MAX_MONEY;
    uint64_t nMaximumCount = 0;
    bool include_unsafe = true;

    std::vector<COutput> vecOutputs;
    {
        CCoinControl cctl;
        cctl.m_avoid_address_reuse = false;
        cctl.m_min_depth = nMinDepth;
        cctl.m_max_depth = nMaxDepth;
        cctl.m_include_unsafe_inputs = include_unsafe;
        LOCK(pwallet->cs_wallet);
        pwallet->AvailableCoins(vecOutputs, &cctl, nMinimumAmount, nMaximumAmount, nMinimumSumAmount, nMaximumCount);
    }

    UniValue results(UniValue::VOBJ);

    // BurnAddress
    CTxDestination dest = DecodeDestination(Params().GetConsensus().cBurnAddress);
    CScript scriptPubKeyBurnAddress = GetScriptForDestination(dest);
    std::vector<std::vector<unsigned char> > vSolutions;
    TxoutType whichType = Solver(scriptPubKeyBurnAddress, vSolutions);
    PKHash keyid = PKHash(uint160(vSolutions[0]));

    //Infinitynode info
    std::map<COutPoint, CInfinitynode> mapInfinitynodes = infnodeman.GetFullInfinitynodeMap();

    // Wallet comments
    std::set<CTxDestination> destinations;
    LOCK(pwallet->cs_wallet);
    for (COutput& out : vecOutputs) {
        CTxDestination addressCoin;
        const CScript& scriptPubKeyCoin = out.tx->tx->vout[out.i].scriptPubKey;
        bool fValidAddress = ExtractDestination(scriptPubKeyCoin, addressCoin);

        if (!fValidAddress || scriptPubKeyCoin.ToString() != scriptPubKeyOwners.ToString())
            continue;

        if (out.tx->tx->vout[out.i].nValue >= nAmount && out.nDepth >= 2) {
            /*check address is unique*/
            for (auto& infpair : mapInfinitynodes) {
                CInfinitynode inf = infpair.second;
                if(inf.getCollateralAddress() == EncodeDestination(addressCoin)){
                    strError = strprintf("Error: Address %s exist in list. Please use another address to make sure it is unique.", EncodeDestination(addressCoin));
                    throw JSONRPCError(RPC_TYPE_ERROR, strError);
                }
            }
            // Wallet comments
            mapValue_t mapValue;
            bool fSubtractFeeFromAmount = true;
            CCoinControl coin_control;
            coin_control.Select(COutPoint(out.tx->GetHash(), out.i));
            coin_control.destChange = NodeOwnerAddress;//fund go back to NodeOwnerAddress

            CScript script;
            script = GetScriptForBurn(keyid, request.params[2].get_str());

            CAmount nFeeRequired;
            FeeCalculation fee_calc_out;
            bilingual_str strErrorRet;

            std::vector<CRecipient> vecSend;
            std::vector<CRecipient> vecSendCopy;
            int nChangePosRet = -1;
            CRecipient recipient = {script, nAmount, fSubtractFeeFromAmount};
            vecSend.push_back(recipient);


            CTransactionRef tx;
            if (!pwallet->CreateTransaction(vecSend, tx, nFeeRequired, nChangePosRet, strErrorRet, coin_control, fee_calc_out, vecSendCopy, true)) {
                throw JSONRPCError(RPC_WALLET_ERROR, strErrorRet.original);
            }

            pwallet->CommitTransaction(tx, std::move(mapValue), {} /* orderForm */);

            results.pushKV("BURNADDRESS", EncodeDestination(dest));
            results.pushKV("BURNPUBLICKEY", HexStr(keyid));
            results.pushKV("BURNSCRIPT", HexStr(scriptPubKeyBurnAddress));
            results.pushKV("BURNTX", tx->GetHash().GetHex());
            results.pushKV("OWNER_ADDRESS",EncodeDestination(NodeOwnerAddress));
            results.pushKV("BACKUP_ADDRESS",EncodeDestination(BKaddress));

            return results;
        }
    }

    return NullUniValue;
},
    };
}

/**
 * @xtdevcoin
 * this function help user burn correctly their funds to update metadata of DIN
 */
static RPCHelpMan infinitynodeupdatemeta()
{
    return RPCHelpMan{"infinitynodeupdatemeta",
                "\nBurn funds to update metadata of DIN.\n"
                "\nReturns JSON info or Null.\n",
                {
                    {"nodeowneraddress", RPCArg::Type::STR, RPCArg::Optional::NO, "Address of owner which burnt funds (will receive the reward)."},
                    {"publickey", RPCArg::Type::STR, RPCArg::Optional::NO, "Address of node (will receive the small reward)"},
                    {"nodeip", RPCArg::Type::STR, RPCArg::Optional::NO, "Ip of node"},
                    {"nodeid", RPCArg::Type::STR, RPCArg::Optional::NO, "First 16 characters of BurnTx (to create node)"},
                },
                RPCResult{
                        RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::STR, "METADATA", "The metadata of DIN which will be sent to network"},
                        },
                },
                RPCExamples{
                    "\nBurn 25 SIN coins to update metadata of DIN\n"
                    + HelpExampleCli("infinitynodeupdatemeta", "nodeowneraddress publickey xxx.xxx.xxx.xxx ABCDABCDABCDABCD")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    UniValue results(UniValue::VOBJ);

    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CWallet* const pwallet = wallet.get();

    NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureAnyChainman(request.context);

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    // Grab locks here as BlockUntilSyncedToCurrentChain() handles them on its own, but we need them for most other funcs
    LOCK2(pwallet->cs_wallet, cs_main);

    const std::string strOwnerAddress = request.params[0].get_str();
    CTxDestination NodeOwnerAddress = DecodeDestination(strOwnerAddress);
    if (!IsValidDestination(NodeOwnerAddress)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Sinovate address: ") + strOwnerAddress);
    }
    CScript scriptPubKeyOwners = GetScriptForDestination(NodeOwnerAddress);

    //limit data carrier, so we accept only 66 char
    std::string nodePublickey = "";
    if(request.params[1].get_str().length() == 44){
        nodePublickey = request.params[1].get_str();
    } else {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid node publickey");
    }

    std::string strService = request.params[2].get_str();
    CService service;
    if(Params().NetworkIDString() != CBaseChainParams::REGTEST) {
        if (!Lookup(strService.c_str(), service, 0, false)){
               throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid IP address");
        }
    }
    CAddress addMeta = CAddress(service, NODE_NETWORK);

    std::string burnfundTxID = "";
    if(request.params[3].get_str().length() == 16){
        burnfundTxID = request.params[3].get_str();
    } else {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "node BurnFundTx ID is invalid. Please enter first 16 characters of BurnFundTx");
    }

    std::string metaID = strprintf("%s-%s", strOwnerAddress, burnfundTxID);
    CMetadata myMeta = infnodemeta.Find(metaID);
    int nCurrentHeight = chainman.ActiveChain().Height();
    if(myMeta.getMetadataHeight() > 0 && nCurrentHeight < myMeta.getMetadataHeight() + Params().MaxReorganizationDepth() * 2){
        int nWait = myMeta.getMetadataHeight() + Params().MaxReorganizationDepth() * 2 - nCurrentHeight;
        std::string strError = strprintf("Error: Please wait %d blocks and try to update again.", nWait);
        throw JSONRPCError(RPC_TYPE_ERROR, strError);
    }

    //check ip and pubkey dont exist
    bool fExistMetaID = false;
    std::map<COutPoint, CInfinitynode> mapInfinitynodes = infnodeman.GetFullInfinitynodeMap();
    for (auto& infnodepair : mapInfinitynodes) {
        if(infnodepair.second.getMetaID() == metaID) fExistMetaID = true;
    }

    //check in NonMaturedMap
    if(!fExistMetaID){
        std::map<COutPoint, CInfinitynode> mapInfNonMatured = infnodeman.GetFullInfinitynodeNonMaturedMap();
        for (auto& infnodepair : mapInfNonMatured) {
            if(infnodepair.second.getMetaID() == metaID) fExistMetaID = true;
        }
    }

    //MetaID does not exist
    if(!fExistMetaID){
        std::string strError = strprintf("Error: MetadataID:%s does not exist in network", metaID);
        throw JSONRPCError(RPC_TYPE_ERROR, strError);
    }

    if(Params().NetworkIDString() != CBaseChainParams::REGTEST) {
        std::map<std::string, CMetadata> mapInfMetadata = infnodemeta.GetFullNodeMetadata();
        for (auto& infmetapair : mapInfMetadata) {
            CMetadata mv = infmetapair.second;
            CAddress addv = CAddress(infmetapair.second.getService(), NODE_NETWORK);
            //found metaID => check expire or not
            if (mv.getMetaID() != metaID && (mv.getMetaPublicKey() == nodePublickey || addMeta.ToStringIP() == addv.ToStringIP())) {
                //change consensus for update metadata at the same POS4 height
                if(nCurrentHeight < Params().GetConsensus().nINMetaUpdateChangeHeight){
                    std::string strError = strprintf("Error: Pubkey or Ip address already exist in network");
                    throw JSONRPCError(RPC_TYPE_ERROR, strError);
                } else {
                    if(mv.getMetaPublicKey() == nodePublickey){
                        std::string strError = strprintf("Error: Pubkey already exist in network");
                        throw JSONRPCError(RPC_TYPE_ERROR, strError);
                    } else if(addMeta.ToStringIP() == addv.ToStringIP()){
                        for (auto& infnodepair : mapInfinitynodes) {
                            if (infnodepair.second.getMetaID() == mv.getMetaID() && infnodepair.second.getExpireHeight() >= nCurrentHeight) {
                                std::string strError = strprintf("Error: IP address already exist in network for non expired node");
                                throw JSONRPCError(RPC_TYPE_ERROR, strError);
                            }
                        }
                    }
                }
            }
        }
    }

    EnsureWalletIsUnlocked(*pwallet);

    std::string strError;
    int nMinDepth = 1;
    int nMaxDepth = 9999999;
    CAmount nMinimumAmount = 0;
    CAmount nMaximumAmount = MAX_MONEY;
    CAmount nMinimumSumAmount = MAX_MONEY;
    uint64_t nMaximumCount = 0;
    bool include_unsafe = true;

    std::vector<COutput> vecOutputs;
    {
        CCoinControl cctl;
        cctl.m_avoid_address_reuse = false;
        cctl.m_min_depth = nMinDepth;
        cctl.m_max_depth = nMaxDepth;
        cctl.m_include_unsafe_inputs = include_unsafe;
        LOCK(pwallet->cs_wallet);
        pwallet->AvailableCoins(vecOutputs, &cctl, nMinimumAmount, nMaximumAmount, nMinimumSumAmount, nMaximumCount);
    }

    // cMetadataAddress
    CTxDestination dest = DecodeDestination(Params().GetConsensus().cMetadataAddress);
    CScript scriptPubKeyMetaAddress = GetScriptForDestination(dest);
    std::vector<std::vector<unsigned char> > vSolutions;
    TxoutType whichType = Solver(scriptPubKeyMetaAddress, vSolutions);
    PKHash keyid = PKHash(uint160(vSolutions[0]));

    std::ostringstream streamInfo;

    for (COutput& out : vecOutputs) {
        CTxDestination addressCoin;
        const CScript& scriptPubKeyCoin = out.tx->tx->vout[out.i].scriptPubKey;
        bool fValidAddress = ExtractDestination(scriptPubKeyCoin, addressCoin);

        if (!fValidAddress || scriptPubKeyCoin.ToString() != scriptPubKeyOwners.ToString())
            continue;

        //use coin with limit value
        if (out.tx->tx->vout[out.i].nValue / COIN >= Params().GetConsensus().nInfinityNodeUpdateMeta
            && out.tx->tx->vout[out.i].nValue / COIN < Params().GetConsensus().nInfinityNodeUpdateMeta*100
            && out.nDepth >= 2) {

            CAmount nAmount = Params().GetConsensus().nInfinityNodeUpdateMeta*COIN;

            // Wallet comments
            mapValue_t mapValue;
            bool fSubtractFeeFromAmount = true;
            CCoinControl coin_control;
            coin_control.Select(COutPoint(out.tx->GetHash(), out.i));
            coin_control.destChange = NodeOwnerAddress;//fund go back to NodeOwnerAddress

            streamInfo << nodePublickey << ";" << strService << ";" << burnfundTxID;
            std::string strInfo = streamInfo.str();
            CScript script;
            script = GetScriptForBurn(keyid, streamInfo.str());

            CAmount nFeeRequired;
            FeeCalculation fee_calc_out;
            bilingual_str strErrorRet;

            std::vector<CRecipient> vecSend;
            std::vector<CRecipient> vecSendCopy;
            int nChangePosRet = -1;
            CRecipient recipient = {script, nAmount, fSubtractFeeFromAmount};
            vecSend.push_back(recipient);

            CTransactionRef tx;
            if (!pwallet->CreateTransaction(vecSend, tx, nFeeRequired, nChangePosRet, strErrorRet, coin_control, fee_calc_out, vecSendCopy, true)) {
                throw JSONRPCError(RPC_WALLET_ERROR, strErrorRet.original);
            }

            pwallet->CommitTransaction(tx, std::move(mapValue), {});

            results.pushKV("METADATA",streamInfo.str());

            return results;
        }
    }

    return NullUniValue;
},
    };
}


/**
 * @xtdevcoin co-authored by @giaki3003
 * this function help user burn correctly their funds to run infinity node
 * (giaki3003) from an array of inputs, without signing
 */
static RPCHelpMan infinitynodeburnfund_external()
{
    return RPCHelpMan{"infinitynodeburnfund_external",
                "\nPrepare a burn transaction with the given inputs.\n"
                "\nReturns JSON info or Null.\n",
                {
                    {"inputs", RPCArg::Type::ARR, RPCArg::Optional::NO, "Specify inputs, a json array of json objects",
                        {
                            {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction id"},
                            {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "The output number"},
                            {"sequence", RPCArg::Type::NUM, RPCArg::Optional::NO, "The sequence number"},
                        },
                    },
                    {"nodeowneraddress", RPCArg::Type::STR, RPCArg::Optional::NO, "Address of owner (will receive the reward)."},
                    {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "The amount in " + CURRENCY_UNIT + " to create Node (Example: 100000). "},
                    {"backupaddress", RPCArg::Type::STR, RPCArg::Optional::NO, "backup of owner address"},
                },
                RPCResult{
                        RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::STR, "rawMetaTx", "raw transaction"},
                            {RPCResult::Type::STR, "BURNADDRESS", "The BURNADDRESS of sinovate network"},
                            {RPCResult::Type::STR_HEX, "BURNPUBLICKEY", "The public key of owner"},
                            {RPCResult::Type::STR_HEX, "BURNSCRIPT", "The script of burn"},
                            {RPCResult::Type::STR, "BACKUPADDRESS", "The BACKUPADDRESS of owner (use in next feature)"},
                        },
                },
                RPCExamples{
                    "\nBurn 1 Milion SIN coins to create BIG Infinitynode\n"
                    + HelpExampleCli("infinitynodeburnfund_external", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\" NodeOwnerAddress 1000000 SINBackupAddress")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{

    if(request.params[0].isNull()) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid inputs");
    }
    RPCTypeCheckArgument(request.params[0], UniValue::VARR);
    UniValue inputs = request.params[0].get_array();

    const std::string address = request.params[1].get_str();
    CTxDestination NodeOwnerAddress = DecodeDestination(address);
    if (!IsValidDestination(NodeOwnerAddress)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Sinovate address: ") + address);
    }

    CAmount nAmount = AmountFromValue(request.params[2]);
    if (nAmount != Params().GetConsensus().nMasternodeBurnSINNODE_1 * COIN &&
        nAmount != Params().GetConsensus().nMasternodeBurnSINNODE_5 * COIN &&
        nAmount != Params().GetConsensus().nMasternodeBurnSINNODE_10 * COIN)
    {
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount to burn and run an InfinityNode");
    }

    const std::string addressbk = request.params[3].get_str();
    CTxDestination BKaddress = DecodeDestination(addressbk);
    if (!IsValidDestination(BKaddress))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid SIN address as SINBackupAddress");

    UniValue results(UniValue::VOBJ);

    // BurnAddress
    CTxDestination dest = DecodeDestination(Params().GetConsensus().cBurnAddress);
    CScript scriptPubKeyBurnAddress = GetScriptForDestination(dest);
    std::vector<std::vector<unsigned char> > vSolutions;
    TxoutType whichType = Solver(scriptPubKeyBurnAddress, vSolutions);
    PKHash keyid = PKHash(uint160(vSolutions[0]));

    CScript script;
    script = GetScriptForBurn(keyid, request.params[3].get_str());

    CMutableTransaction rawMetaTx = ConstructTransactionWithScript(request.params[0], script);

    results.pushKV("rawMetaTx", EncodeHexTx(CTransaction(rawMetaTx)));
    results.pushKV("BURNADDRESS", EncodeDestination(dest));
    results.pushKV("BURNPUBLICKEY", HexStr(keyid));
    results.pushKV("BURNSCRIPT", HexStr(scriptPubKeyBurnAddress));
    results.pushKV("BACKUP_ADDRESS",EncodeDestination(BKaddress));

    return results;
},
    };
}

static RPCHelpMan infinitynodeupdatemeta_external()
{
    return RPCHelpMan{"infinitynodeupdatemeta_external",
                "\nPrepare a metadata update transaction with the given inputs.\n"
                "\nReturns JSON info or Null.\n",
                {
                    {"inputs", RPCArg::Type::ARR, RPCArg::Optional::NO, "Specify inputs, a json array of json objects",
                        {
                            {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction id"},
                            {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "The output number"},
                            {"sequence", RPCArg::Type::NUM, RPCArg::Optional::NO, "The sequence number"},
                        },
                    },
                    {"nodeowneraddress", RPCArg::Type::STR, RPCArg::Optional::NO, "Address of owner which burnt funds (will receive the reward)."},
                    {"publickey", RPCArg::Type::STR, RPCArg::Optional::NO, "Address of node (will receive the small reward)"},
                    {"nodeip", RPCArg::Type::STR, RPCArg::Optional::NO, "Ip of node"},
                    {"nodeid", RPCArg::Type::STR, RPCArg::Optional::NO, "First 16 characters of BurnTx (to create node)"},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "Update message", "(UpdateInfo) Update message"},
                    },
                },
                RPCExamples{
                    "\nBurn 25 SIN coins to update metadata of DIN\n"
                    + HelpExampleCli("infinitynodeburnfund_external", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\" nodeowneraddress  publickey nodeip nodeid")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    UniValue results(UniValue::VOBJ);

    NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureAnyChainman(request.context);


    if(request.params[0].isNull()) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid inputs");
    }
    RPCTypeCheckArgument(request.params[0], UniValue::VARR);
    UniValue inputs = request.params[0].get_array();

    std::string strOwnerAddress = request.params[1].get_str();
    CTxDestination INFAddress = DecodeDestination(strOwnerAddress);
    if (!IsValidDestination(INFAddress)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid OwnerAddress");
    }

    //limit data carrier, so we accept only 66 char
    std::string nodePublickeyHexStr = "";
    if(request.params[2].get_str().length() == 44){
        nodePublickeyHexStr = request.params[2].get_str();
    } else {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid node publickey");
    }

    std::string strService = request.params[3].get_str();
    CService service;
    if(Params().NetworkIDString() != CBaseChainParams::REGTEST) {
        if (!Lookup(strService.c_str(), service, 0, false)){
               throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid IP address");
        }
    }
    CAddress addMeta = CAddress(service, NODE_NETWORK);

    std::string burnfundTxID = "";
    if(request.params[4].get_str().length() == 16){
        burnfundTxID = request.params[4].get_str();
    } else {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "node BurnFundTx ID is invalid. Please enter first 16 characters of BurnFundTx");
    }

    std::string metaID = strprintf("%s-%s", strOwnerAddress, burnfundTxID);
    CMetadata myMeta = infnodemeta.Find(metaID);
    int nCurrentHeight = chainman.ActiveChain().Height();
    if(myMeta.getMetadataHeight() > 0 && nCurrentHeight < myMeta.getMetadataHeight() + Params().MaxReorganizationDepth() * 2){
        int nWait = myMeta.getMetadataHeight() + Params().MaxReorganizationDepth() * 2 - nCurrentHeight;
        std::string strError = strprintf("Error: Please wait %d blocks and try to update again.", nWait);
        throw JSONRPCError(RPC_TYPE_ERROR, strError);
    }

    //check ip and pubkey dont exist
    if(Params().NetworkIDString() != CBaseChainParams::REGTEST) {
        std::map<std::string, CMetadata> mapInfMetadata = infnodemeta.GetFullNodeMetadata();
        for (auto& infmetapair : mapInfMetadata) {
            CMetadata m = infmetapair.second;
            CAddress add = CAddress(infmetapair.second.getService(), NODE_NETWORK);
            //found metaID => check expire or not
            if (m.getMetaID() != metaID && (m.getMetaPublicKey() == nodePublickeyHexStr || addMeta.ToStringIP() == add.ToStringIP())) {
                std::map<COutPoint, CInfinitynode> mapInfinitynodes = infnodeman.GetFullInfinitynodeMap();
                for (auto& infnodepair : mapInfinitynodes) {
                    if (infnodepair.second.getMetaID() == m.getMetaID() && infnodepair.second.getExpireHeight() >= nCurrentHeight) {
                        std::string strError = strprintf("Error: Pubkey or IP address already exist in network");
                        throw JSONRPCError(RPC_TYPE_ERROR, strError);
                    }
                }
            }
        }
    }

    // cMetadataAddress
    CTxDestination dest = DecodeDestination(Params().GetConsensus().cMetadataAddress);
    CScript scriptPubKeyMetaAddress = GetScriptForDestination(dest);
    std::vector<std::vector<unsigned char> > vSolutions;
    TxoutType whichType = Solver(scriptPubKeyMetaAddress, vSolutions);
    PKHash keyid = PKHash(uint160(vSolutions[0]));

    std::ostringstream streamInfo;

    streamInfo << nodePublickeyHexStr << ";" << strService << ";" << burnfundTxID;
    std::string strInfo = streamInfo.str();
    CScript script;
    script = GetScriptForBurn(keyid, streamInfo.str());

    CMutableTransaction rawMetaTx = ConstructTransactionWithScript(request.params[0], script);

    results.pushKV("rawMetaTx", EncodeHexTx(CTransaction(rawMetaTx)));

    return results;
},
    };
}


void RegisterInfinitynodeRPCCommands(CRPCTable &t)
{
// clang-format off
static const CRPCCommand commands[] =
{ //  category              actor (function)
//  --------------------- ------------------------
  { "infinitynode",            &infinitynode,                     },
  { "infinitynode",            &infinitynodeburnfund,             },
  { "infinitynode",            &infinitynodeupdatemeta,           },
  { "infinitynode",            &infinitynodeburnfund_external,    },
  { "infinitynode",            &infinitynodeupdatemeta_external,  },
};
// clang-format on
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
