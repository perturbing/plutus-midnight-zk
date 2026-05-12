{-# LANGUAGE NumericUnderscores #-}

module BenchCommon (TestSize (..), printHeader, printSizeStatistics) where

import qualified Data.ByteString as BS
import Data.SatInt (fromSatInt)
import PlutusCore.Evaluation.Machine.ExBudget (ExBudget (..), exBudgetCPU, exBudgetMemory)
import qualified PlutusCore.Evaluation.Machine.ExBudgetingDefaults as PLC
import PlutusCore.Evaluation.Machine.ExMemory (ExCPU (..), ExMemory (..))
import qualified PlutusCore.Flat as Flat
import System.IO (Handle)
import Text.Printf (hPrintf, printf)
import qualified UntypedPlutusCore as UPLC
import qualified UntypedPlutusCore.Evaluation.Machine.Cek as Cek

-- Protocol parameters (Cardano mainnet)
maxTxSize, maxTxExSteps, maxTxExMem :: Integer
maxTxSize = 16_384
maxTxExSteps = 10_000_000_000
maxTxExMem = 16_500_000

data TestSize = NoSize | TestSize Integer

stringOfTestSize :: TestSize -> String
stringOfTestSize NoSize = "-"
stringOfTestSize (TestSize n) = show n

percentage :: (Integral a, Integral b) => a -> b -> Double
percentage a b = fromIntegral a * 100 / fromIntegral b

percentTxt :: (Integral a, Integral b) => a -> b -> String
percentTxt a b = printf "(%.1f%%)" (percentage a b)

toAnonDeBruijnProg ::
    UPLC.Program UPLC.NamedDeBruijn UPLC.DefaultUni UPLC.DefaultFun () ->
    UPLC.Program UPLC.DeBruijn UPLC.DefaultUni UPLC.DefaultFun ()
toAnonDeBruijnProg (UPLC.Program ann ver body) =
    UPLC.Program ann ver $
        UPLC.termMapNames (\(UPLC.NamedDeBruijn _ ix) -> UPLC.DeBruijn ix) body

getCostsCek ::
    UPLC.Program UPLC.NamedDeBruijn UPLC.DefaultUni UPLC.DefaultFun () ->
    (Integer, Integer)
getCostsCek (UPLC.Program _ _ term) =
    let report = Cek.runCekDeBruijn PLC.defaultCekParametersForTesting Cek.counting Cek.noEmitter term
        Cek.CountingSt budget = Cek._cekReportCost report
        ExCPU cpuSat = exBudgetCPU budget
        ExMemory memSat = exBudgetMemory budget
     in (fromSatInt cpuSat, fromSatInt memSat)

printHeader :: Handle -> IO ()
printHeader h = do
    hPrintf h "    n     Script size             CPU usage               Memory usage\n"
    hPrintf h "  ----------------------------------------------------------------------\n"

printSizeStatistics ::
    Handle ->
    TestSize ->
    UPLC.Program UPLC.NamedDeBruijn UPLC.DefaultUni UPLC.DefaultFun () ->
    IO ()
printSizeStatistics h n script = do
    let serialised = Flat.flat (UPLC.UnrestrictedProgram (toAnonDeBruijnProg script))
        size = BS.length serialised
        (cpu, mem) = getCostsCek script
    hPrintf
        h
        "  %3s %7d %8s %15d %8s %15d %8s \n"
        (stringOfTestSize n)
        size
        (percentTxt size maxTxSize)
        cpu
        (percentTxt cpu maxTxExSteps)
        mem
        (percentTxt mem maxTxExMem)
