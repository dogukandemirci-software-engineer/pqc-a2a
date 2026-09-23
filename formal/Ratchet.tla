------------------------------ MODULE Ratchet ------------------------------
EXTENDS Naturals, FiniteSets

CONSTANT Tokens
ASSUME Tokens # {}

fresh == "fresh"
sent == "sent"
consumed == "consumed"
none == 0

VARIABLES sChain, rChain, tokenState, pending, opened, goodAttempts, badAttempts, lastAction, badSnapshot
vars == <<sChain, rChain, tokenState, pending, opened, goodAttempts, badAttempts, lastAction, badSnapshot>>

Init ==
    /\ sChain = 0
    /\ rChain = 0
    /\ tokenState = [t \in Tokens |-> fresh]
    /\ pending = none
    /\ opened = {}
    /\ goodAttempts = 0
    /\ badAttempts = 0
    /\ lastAction = "init"
    /\ badSnapshot = [t \in Tokens |-> fresh]

Send(t) ==
    /\ t \in Tokens
    /\ sChain < 2
    /\ tokenState[t] = fresh
    /\ pending = none
    /\ tokenState' = [tokenState EXCEPT ![t] = sent]
    /\ pending' = t
    /\ sChain' = sChain + 1
    /\ lastAction' = "send"
    /\ UNCHANGED <<rChain, opened, goodAttempts, badAttempts, badSnapshot>>

OpenBad ==
    /\ pending # none
    /\ badAttempts < 2
    /\ badAttempts' = badAttempts + 1
    /\ lastAction' = "bad"
    /\ badSnapshot' = tokenState
    /\ UNCHANGED <<sChain, rChain, tokenState, pending, opened, goodAttempts>>

OpenGood ==
    /\ pending # none
    /\ pending \notin opened
    /\ tokenState[pending] = sent
    /\ tokenState' = [tokenState EXCEPT ![pending] = consumed]
    /\ opened' = opened \cup {pending}
    /\ rChain' = rChain + 1
    /\ goodAttempts' = goodAttempts + 1
    /\ pending' = none
    /\ lastAction' = "good"
    /\ UNCHANGED <<sChain, badAttempts, badSnapshot>>

Next ==
    \/ \E t \in Tokens : Send(t)
    \/ OpenBad
    \/ OpenGood

TypeOK ==
    /\ sChain \in Nat
    /\ rChain \in Nat
    /\ tokenState \in [Tokens -> {fresh, sent, consumed}]
    /\ pending \in Tokens \cup {none}
    /\ opened \subseteq Tokens
    /\ goodAttempts \in Nat
    /\ badAttempts \in Nat
    /\ lastAction \in {"init", "send", "bad", "good"}
    /\ badSnapshot \in [Tokens -> {fresh, sent, consumed}]

NoConsumeOnBad ==
    lastAction = "bad" => tokenState = badSnapshot

SingleUse ==
    Cardinality(opened) = goodAttempts

ReceiverNeverAhead ==
    rChain <= sChain

TokenConsistency ==
    \A t \in Tokens :
        tokenState[t] = consumed => t \in opened

=============================================================================
