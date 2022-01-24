// Copyright (c) 2018-2019 SIN developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <util/translation.h>
#include <sinovate/infwalletaccess.h>
#include <sinovate/infinitynodelockreward.h>
#include <sinovate/infinitynodepeer.h>

CInfWalletAccess infWalletAccess;

std::shared_ptr<CWallet> CInfWalletAccess::GetWalletAcces() const{
    std::vector<std::shared_ptr<CWallet>> wallets = GetWallets();
    std::shared_ptr<CWallet> pwallet = (wallets.size() > 0) ? wallets[0] : nullptr;
    return pwallet;
}

bool CInfWalletAccess::IsWalletlocked(const CWallet* pwallet)
{
    LOCK(pwallet->cs_wallet);

    return pwallet->IsLocked();
}

bool CInfWalletAccess::IsMineNodeAddress(const CWallet* pwallet, CTxDestination dest)
{
    LOCK(pwallet->cs_wallet);

    isminetype mine = pwallet->IsMine(dest);
    bool check = bool(mine & ISMINE_SPENDABLE);
    return check;
}

bool CInfWalletAccess::IsBalancePositive(const CWallet* pwallet)
{
    LOCK(pwallet->cs_wallet);

    const auto bal = pwallet->GetBalance();
    return (bal.m_mine_trusted > 0);
}

bool CInfWalletAccess::RegisterLROnchain()
{
    if(!fInfinityNode) return false;

    std::string sLRInfo;
    COutPoint infCheck;
    inflockreward.getRegisterInfo(sLRInfo, infCheck);

    std::shared_ptr<CWallet> const wallet = infWalletAccess.GetWalletAcces();
    if(!wallet){
        LogPrint(BCLog::INFINITYWA,"CInfinityNodeWalletAccess::RegisterLROnchain -- No wallet is loaded. Please complete json file\n");
        return false;
    }

    CWallet* const pwallet = wallet.get();
    LOCK(pwallet->cs_wallet);

    if(pwallet->IsLocked()){
        LogPrint(BCLog::INFINITYWA,"CInfinityNodeWalletAccess::RegisterLROnchain -- Wallet is locked\n");
        return false;
    }

    CTxDestination nodeDest = GetDestinationForKey(infinitynodePeer.pubKeyInfinitynode, OutputType::LEGACY);
    isminetype mine = pwallet->IsMine(nodeDest);
    bool check = bool(mine & ISMINE_SPENDABLE);
    if(!check){
        LogPrint(BCLog::INFINITYWA,"CInfinityNodeWalletAccess::RegisterLROnchain -- Node PivateKey is not mine or not spendable\n");
        return false;
    }

    const auto bal = pwallet->GetBalance();
    if(bal.m_mine_trusted == 0){
        LogPrint(BCLog::INFINITYWA,"CInfinityNodeWalletAccess::RegisterLROnchain -- Balance is 0\n");
        return false;
    }

    LogPrint(BCLog::INFINITYWA,"CInfinityNodeWalletAcces::RegisterLROnchain -- Register: %s, OutPoint: %s\n", sLRInfo, infCheck.ToStringFull());
    if(sLRInfo == "" || sLRInfo.empty()){
        LogPrint(BCLog::INFINITYWA,"CInfinityNodeWalletAccess::RegisterLROnchain -- Nothing to register!!!\n");
        return false;
    }

    if(infinitynodePeer.burntx != infCheck) {
        LogPrint(BCLog::INFINITYWA,"CInfinityNodeWalletAccess::RegisterLROnchain -- I am not INFINITY NODE: %s\n", infCheck.ToStringFull());
        return false;
    }

    if(infinitynodePeer.nState != INFINITYNODE_PEER_STARTED){
        LogPrint(BCLog::INFINITYWA,"CInfinityNodeWalletAccess::RegisterLROnchain -- INFINITY NODE is not started\n");
        return false;
    }

    bilingual_str strError;
    mapValue_t mapValue;

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
    CTransactionRef tx_New;
    CCoinControl coin_control;

    CAmount nFeeRet = 0;
    bool fSubtractFeeFromAmount = false;
    int nChangePosRet = -1;
    CAmount nFeeRequired;
    CAmount curBalance = pwallet->GetAvailableBalance();

    CAmount nAmountRegister = 0.001 * COIN;
    CAmount nAmountToSelect = 0.05 * COIN;

    CScript nodeScript = GetScriptForDestination(nodeDest);

    //select coin from Node Address, accept only this address
    CAmount selected = 0;
    int nInput = 0;
    for (COutput& out : vecOutputs) {
        if(selected >= nAmountToSelect) break;
        if(out.nDepth >= 2 && selected < nAmountToSelect){
            CScript pubScript;
            pubScript = out.tx->tx->vout[out.i].scriptPubKey;
            if(pubScript == nodeScript){
                coin_control.Select(COutPoint(out.tx->GetHash(), out.i));
                selected += out.tx->tx->vout[out.i].nValue;
                nInput++;
            }
        }
    }

    if(selected < nAmountToSelect){
        LogPrint(BCLog::INFINITYWA,"CInfinityNodeWalletAccess::RegisterLROnchain -- Balance of Infinitynode is not enough.\n");
        return false;
    }

    //chang address
    coin_control.destChange = nodeDest;

    //CRecipient
    std::string strFail = "";
    std::vector<CRecipient> vecSend;
    std::vector<CRecipient> vecSendCopy;

    CTxDestination dest = DecodeDestination(Params().GetConsensus().cLockRewardAddress);
    CScript scriptPubKeyBurnAddress = GetScriptForDestination(dest);
    std::vector<std::vector<unsigned char> > vSolutions;
    TxoutType whichType = Solver(scriptPubKeyBurnAddress, vSolutions);
    PKHash keyid = PKHash(uint160(vSolutions[0]));
    CScript script;
    script = GetScriptForBurn(keyid, sLRInfo);

    CRecipient recipient = {script, nAmountRegister, fSubtractFeeFromAmount};
    vecSend.push_back(recipient);
    FeeCalculation fee_calc_out;

    mapValue["to"] = Params().GetConsensus().cLockRewardAddress;
    //Transaction
    CTransactionRef tx;
    if (!pwallet->CreateTransaction(vecSend, tx, nFeeRequired, nChangePosRet, strError, coin_control, fee_calc_out, vecSendCopy, true)) {
        LogPrint(BCLog::INFINITYWA,"CInfinityNodeWalletAccess::RegisterLROnchain -- Can not create tx: %s (nb input: %s Amount: %lld)\n",strError.original, nInput, selected);
        return false;
    }

    pwallet->CommitTransaction(tx, std::move(mapValue), {} /* orderForm */);

    sLRInfo = "";
    infCheck = COutPoint();
    inflockreward.setRegisterInfo(sLRInfo, infCheck);

    return true;
}

void CInfWalletAccess::UpdatedBlockTip(const CBlockIndex *pindex)
{
    if(!pindex) return;
    LOCK(cs);
    nCachedBlockHeight = pindex->nHeight;
}
