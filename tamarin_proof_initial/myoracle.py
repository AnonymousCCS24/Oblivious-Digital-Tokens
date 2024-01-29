#!/usr/bin/env python

import sys
import re

#error =

lines = sys.stdin.readlines()

l1 = []
l2 = []
l3 = []
l4 = []
l5 = []
l6 = []
l7 = []
l8 = []
l9 = []
l10 = []
l11 = []
l12 = []
l13 = []
l14 = []
l15 = []
l16 = []
l17 = []
l18 = []
l19 = []
l20 = []


client_2_regex = r"Client_2\( \$C.[0-9], \$E.[0-9], ~ltk.[0-9], \$A.[0-9], server_pk"


lemma = sys.argv[1]

for line in lines:
    num = line.split(":")[0]

    if lemma == "debug_simple":
        pass

    elif lemma == "executable_simple":
        if "Threat_Actor_1" in line:
            l1.append(num)
        elif "NO_Pk" in line:
            l2.append(num)
        elif "!KU( sign(" in line:
            l3.append(num)
        elif "!KU( senc(" in line:
            l4.append(num)

        else:
            pass

    elif lemma == "token_integrity":
        if "!NO_Pk" in line:
            l1.append(num)
        elif "!KU( sign(<OTEE" in line:
            l2.append(num)

    elif lemma == "enclave_randomness_source":
        if "EnclaveChooseHint( enclave_randomness )" in line:
            l1.append(num)
        elif "!KU( sign(<$E, pk(x)>, x.1) ) @ #vk." in line:
            l2.append(num)
        elif "pk(~enclave_ltk)" in line:
            l3.append(num)
        elif "!KU( ~enclave_ltk ) @ #vk." in line:
            l3.append(num)
        elif "Client_2" in line:
            l4.append(num)
        elif "~~>" in line:
            l5.append(num)
        elif "~enclave_ltk" in line:
            l6.append(num)
        elif "IV1," in line:
            l7.append(num)
        elif "NTP_Pk" in line:
            l8.append(num)
        elif "~ltk.1" in line:
            l9.append(num)
        else:
            pass


    elif lemma == "adversaryCannotLearnDeviceDHShareBeforeMeasurement":
        if "splitEqs(0)" in line:
            l1.append(num)
        elif "OTEE_0(" in line:
            l2.append(num)
        elif " !KU( ~x_0" in line:
            l3.append(num)
        else:
            pass


    elif lemma == "twoOTEEsCannotHaveSameShare":
        if "OTEE_0" in line:
            l1.append(num)
        elif "splitEqs(0)" in line:
            l2.append(num)
        elif "OTEEIn" in line and "#i" in line:
            l3.append(num)
        elif " !KU( DHE^" in line:
            l4.append(num)
        elif "OTEE_3(" in line:
            l5.append(num)

        elif " !KU( x^(x.1" in line:
            l7.append(num)
        elif " !KU( x^inv" in line:
            l7.append(num)
        elif " !KU( x.1^" in line:
            l7.append(num)
        elif " !KU( 'g'^(~x" in line:
            l7.append(num)

        elif "OTEEIn" in line and "#j" in line:
            l8.append(num)
        elif " !KU( X_1^" in line:
            l9.append(num)
        elif " !KU( X_1_2^" in line:
            l9.append(num)


        elif "splitEqs(1)" in line:
            l10.append(num)


        elif " !KU( sign(" in line:
            l13.append(num)

        elif " !KU( senc(sign" in line:
            l14.append(num)

        else:
            pass


    elif lemma == "OTEEOrder":
        if "OTEESession" in line:
            l1.append(num)
        elif "OTEE_0" in line:
            l2.append(num)
        elif "OTEE_3" in line:
            l3.append(num)
        else:
            pass

    elif lemma == "adversaryCannotKnowDHEOfHonestOTEEAndThreatAgent":
        if "OTEESession" in line:
            l1.append(num)
        elif "!KU( 'g'^(~x_0*!x_1) )" in line:
            l2.append(num)
        elif "OTEE_0" in line:
            l3.append(num)
        elif " !KU( ~x_0 )" in line:
            l4.append(num)
        else:
            pass

    elif lemma == "ifOTEEConnectsToServerThenShareMustBeOutputByTheServer":
        if "OTEEIn" in line:
            l1.append(num)
        elif "!KU( senc(sign" in line:
            l2.append(num)
        elif "!KU( sign(" in line:
            l3.append(num)
        else:
            pass

    elif lemma == "ifServerAndOTEEHaveSameKeyThenTHeyCommunicated":
        if "~ltk" in line:
            l1.append(num)
        elif "OTEE_0" in line:
            l2.append(num)
        elif "OTEEIn" in line:
            l3.append(num)
        elif "!KU( senc(sign" in line:
            l4.append(num)
        elif "!KU( sign(" in line:
            l5.append(num)
        elif "splitEqs(0)" in line:
            l6.append(num)
        elif "splitEqs(1)" in line:
            l7.append(num)
        elif "~x_0" in line and "~x_1" in line and not "¬" in line and not "hmac" in line:
            l8.append(num)
        elif "OTEE_3" in line:
            l9.append(num)
        elif "!KU( derive_secret" in line and "'s_hs_traffic'" in line:
            l10.append(num)
        elif "!KU( 'g'^x.1" in line:
            l11.append(num)
        elif "inv(~x_1)" in line:
            l12.append(num)
        elif "inv((~x_1" in line:
            l13.append(num)


        elif True:
            pass

        elif "DHE" in line:
            l3.append(num)
        elif "senc(sign" in line:
            l4.append(num)
        elif "sign(<" in line:
            l4.append(num)
        elif "derive_secret" in line:
            l5.append(num)
        elif "inv(~x_0)" in line or "inv(~x_1)" in line:
            l6.append(num)
        elif "OTEE_0" in line:
            l7.append(num)
        elif "!KU( 'g'^(~x_0*x_1)" in line:
            l8.append(num)
        elif "~x_0" in line or "~x_1" in line:
            l9.append(num)
        else:
            pass

    elif lemma == "AdversaryKnowsDHEOnlyIfItKnowsTheShare":
        if "OTEE_0" in line:
            l1.append(num)
        elif " !KU( 'g'^(~x_0*~x_1)" in line:
            l2.append(num)
        elif "splitEqs(0)" in line:
            l3.append(num)
        elif " !KU( 'g'^(~x_0*x_1)" in line:
            l4.append(num)
        elif " !KU( 'g'^(x.1*inv(~x_0))" in line:
            l5.append(num)
        elif " !KU( 'g'^inv((~x_0*x.1))" in line:
            l6.append(num)
        elif " !KU( 'g'^(x.1*inv((~x_0*x.2)))" in line:
            l7.append(num)
        else:
            pass

    elif lemma == "twoOTEEsCannotHaveSameDHE":
        if "OTEE_0" in line:
            l1.append(num)
        elif "splitEqs(0)" in line:
            l2.append(num)
        elif "OTEEIn" in line: #and "#i" in line:
            l3.append(num)
#        elif " !KU( DHE^" in line:
#            l4.append(num)
        elif "OTEE_3(" in line:
            l5.append(num)

#        elif " !KU( x^(x.1" in line:
#            l7.append(num)
#        elif " !KU( x^inv" in line:
#            l7.append(num)
#        elif " !KU( x.1^" in line:
#            l7.append(num)

        elif "splitEqs(5)" in line:
            l7.append(num)
#        elif "'g'^(~x_0.1*~x_1.1)" in line:
#            l7.append(num)


        elif "OTEEIn" in line and "#j" in line:
            l8.append(num)
        elif " !KU( X_1^" in line:
            l9.append(num)
        elif " !KU( X_1_2^" in line:
            l9.append(num)
        elif " !KU( DHE^" in line:
            l9.append(num)


#        elif "splitEqs(1)" in line:
#            l10.append(num)


        elif " !KU( sign(" in line:
            l13.append(num)

        elif " !KU( senc(sign" in line:
            l14.append(num)

        elif " !KU( derive_secret" in line:
            l15.append(num)

        elif " splitEqs(1)" in line:
            l16.append(num)

        elif " !KU( 'g'^(~x" in line:
            l17.append(num)

        elif " !KU( x.1^" in line:
            l17.append(num)

        else:
            pass


    elif lemma == "adversaryCannotKnowMeasurementPositionBeforeMeasurement":
        if "Threat_Actor_0" in line:
            l1.append(num)
        elif "OTEEPosition" in line:
            l2.append(num)
        elif "OTEE_2" in line:
            l3.append(num)
        elif " !KU( senc(sign(" in line:
            l4.append(num)
        elif " !KU( select('g'^" in line:
            l5.append(num)
        elif " !KU( 'g'^(~x_0*~x_1)" in line:
            l6.append(num)
        elif " OTEE_3" in line:
            l7.append(num)
        elif " !KU( sign(<<" in line:
            l8.append(num)

        else:
            pass

    elif lemma == "TheMeasurementPositionIsUnique":
        if "OTEEPosition" in line:
            l1.append(num)
        elif "OTEE_2" in line:
            l2.append(num)
        else:
            pass

    elif lemma == "adversaryCannotFindSubsetPropertiesFromThreatActor":
        if "splitEqs(1)" in line:
            l1.append(num)
        elif " !KU( 'g'^inv(" in line or " !KU( 'g'^(" in line or "#vk.2 " in line:
            l2.append(num)
        elif "OTEESessionServerNonce" in line:
            l3.append(num)
        elif "OTEE_2" in line:
            l4.append(num)
        elif " !KU( senc(sign(" in line  or " !KU( sign(" in line:
            l5.append(num)
        elif " !KU( senc(hmac(" in line:
            l6.append(num)
        elif " !KU( measure(select(" in line:
            l7.append(num)
        elif " !KU( select('g'^" in line:
            l8.append(num)

        elif True:
            pass

        elif " !KU( 'g'^~x_1.1" in line:
            l5.append(num)
        elif "Threat_Actor_0" in line or "!KU( ~prop )" in line:
            l6.append(num)
        elif " !KU( measure(select" in line:
            l7.append(num)
        elif " !KU( senc(sign" in line:
            l8.append(num)
        elif " !KU( sign(" in line:
            l9.append(num)

        elif True:
            pass


        elif "OTEESessionServerNonce" in line:
            l1.append(num)
        elif "Threat_Actor_0" in line:
            l2.append(num)
        elif "OTEE_2" in line:
            l2.append(num)
        elif "Agent_2" in line:
            l3.append(num)
        elif " !KU( senc(sign" in line:
            l3.append(num)
        elif " !KU( sign(<" in line:
            l3.append(num)
        elif " !KU( derive_secret" in line:
            l3.append(num)
#        elif "splitEqs(1)" in line:
#            l4.append(num)
        elif " !KU( z" in line or " !KU( x^" in line or " !KU( 'g'^" in line:
            l4.append(num)
        elif "!KU( measure(select(" in line:
            l5.append(num)
        elif "!KU( select(" in line:
            l6.append(num)
        elif "splitEqs(4)" in line:
            l7.append(num)
        elif " !KU( X_0" in line:
            l8.append(num)

        else:
            pass

    elif lemma == "client_id_only_from-client":
        pass # Seems to work by itself

    elif lemma == "adversaryCannotCompromiseVerifierLTK" or lemma == "adversaryCannotCompromiseNTPLTK":
        if " ~ltk" in line:
            l1.append(num)

    elif lemma == "adversaryCannotRecoverClientDHSecret":
        if " ~x_0" in line:
            l1.append(num)

    elif lemma == "adversaryCannotRecoverServerDHSecret":
        if " ~x_1" in line:
            l1.append(num)

    elif lemma == "OTEEsNeverChooseSameSecrets" or lemma == "OTEEChallengeResponseOnlyIfOTEEHello":
        if "OTEE_3" in line or "OTEE_0" in line:
            l1.append(num)

    elif lemma == "DH_source":
        if "splitEqs(0)" in line:
            l1.append(num)

        if "Enclave_0(" in line:
            l2.append(num)

        if "!KU( 'g'^(~x_0*x_1) )" in line:
            l3.append(num)

            #        if "Enclave_3( $E, $C, ~agent_id.2, ~n_0, ~x_0, n_1.1, X_1," in line or "Enclave_3( $E, $C, ~agent_id.2, ~n_0, ~x_0, n_1.2, X_1.1," in line or "Enclave_3( $E, $C, ~agent_id.1, ~n_0, ~x_0, n_1.1, X_1," in line:

        if "Enclave_3( " in line:
            l4.append(num)

        if "EnclaveIn( $E," in line:
            l5.append(num)

        if "!KU( 'g'^(x*inv(~x_0)) )" in line or "!KU( 'g'^(x.1*inv(~x_0)) )" in line or "!KU( 'g'^inv((~x_0*x)) )" in line or "!KU( 'g'^inv((~x_0*x.1)) )" in line or "!KU( 'g'^(x*inv((~x_0*x.1)))" in line or "!KU( 'g'^(x.1*inv((~x_0*x.2)))" in line:
            l6.append(num)


    elif lemma == "adversaryCannotFigureOutMeasurementPositionsBeforeTheMeasurementHappens":
        if "inv(~x_1)" in line:
            l1.append(num)

    elif lemma == "acceptedVerificationOnlyIfCorrectOTEEWasRunning":
        if "!NO_Ltk" in line:
            l1.append(num)
        elif "!NO_Pk" in line:
            l2.append(num)
        elif "Threat_Actor_1(" in line:
            l3.append(num)
        elif "!KU( senc(<y" in line:
            l4.append(num)
        elif "OTEE_3" in line:
            l5.append(num)
        elif "!KU( sign(<OTEE" in line:
            l6.append(num)
        elif "splitEqs(0)" in line:
            l7.append(num)
        elif "!KU( sign(<y" in line:
            l8.append(num)
        elif "!KU( ~OTEE_ltk" in line:
            l9.append(num)

        else:
            pass


    elif lemma == "binding_integrity":

        if "simplify" in line:
            l1.append(num)

        elif "Threat_Actor_1(" in line:
            l2.append(num)

        elif "NO_Pk( $NO, pk(x" in line:
            l3.append(num)

#        elif "!KU( v(~s" in line:
#            l4.append(num)

        elif "!KU( ~OTEE_ltk" in line:
            l4.append(num)

        elif "sign(<OTEE, pk" in line:
            l6.append(num)

        elif "!KU( pk(~OTEE_ltk" in line:
            l7.append(num)

        elif "!KU( senc(<y" in line:
            l8.append(num)

        elif "splitEqs(2)" in line or " !KU( ~prop )" in line:
            l9.append(num)

        elif "!KU( read(select" in line:
            l10.append(num)

        elif "!KU( sign(<y" in line:
            l11.append(num)

        elif " !KU( measure(select" in line:
            l11.append(num)

        elif "senc(sign(<" in line:
            l12.append(num)

        elif True:
            pass

        elif "derive_secret" in line and "c_hs_traffic" in line and not "finished" in line:
            l8.append(num)

        elif "derive_secret" in line and "s_hs_traffic" in line and not "'0'" in line:
            l8.append(num)

        elif " !KU( X_0^~x_1" in line:
            l9.append(num)

        elif "!KU( senc(hmac(" in line:
            l10.append(num)

        elif True:
            pass

        elif "senc(sign(<" in line and "h4(z.1" in line:
            l2.append(num)

        elif "KU( X_0" in line or "KU( z" in line:
            l2.append(num)

        elif "splitEqs(2)" in line:
            l3.append(num)

        elif "select(DHE)," in line and not "finished" in line and not "h4" in line:
            l4.append(num)

        elif "key_der(~hint, ~r) " in line and not "finished" in line:
            l5.append(num)



        elif "<OTEE, pk(~ltk)>" in line:
            l6.append(num)

        elif " DHE " in line:
            l6.append(num)

        elif " ~OTEE_ltk " in line:
            l7.append(num)

        elif " ~prop " in line:
            l8.append(num)

        elif "sign(h1(enclave_randomness," in line:
            l9.append(num)





        elif " sign(<$OTEE, pk(x)>, ~ltk.1) " in line or " sign(<$OTEE, pk(x.1)>, ~ltk.1) " in line or " sign(<$OTEE, pk(x.2)>, ~ltk.1) " in line:
            l13.append(num)

        elif "!KU( sign(<" in line and "measure(select(DHE" in line:
            l11.append(num)

        elif "!NTP_Pk( $NTP, pk(x.1) )" in line:
            l12.append(num)

        elif "splitEqs(1)" in line or "splitEqs(3)" in line:
            l13.append(num)

        elif "senc(hmac" in line:
            l13.append(num)



        elif "!KU( X_0^" in line and not "<" in line:
            l15.append(num)

    elif lemma == "types":
        if "last(#i)" in line and "OUT_Verifier_0( hint, E, ch_prop ) @ #j" in line and "(!KU( hint ) @ #j)" in line and "InvalidChallenge( E, C, hint ) @ #j)" in line:
            l1.append(num)

        elif "last(#i)" in line:
            l2.append(num)

        elif "last(#j)" in line:
            l3.append(num)

        elif "!Enclave_Ltk( $E, ~enclave_ltk )" in line:
            l2.append(num)

        elif "!KU( aenc(hint, pk(~enclave_ltk)) ) @ #vk.1" in line:
            l2.append(num)

        elif "~~>" in line:
            l2.append(num)

        elif "encode_server_hint(derive_secret(DHE," in line:
            l3.append(num)

        elif "!KU( sign(<$E.2, pk(~enclave_ltk)>, ~ltk)" in line:
            l3.append(num)

        elif "(OUT_Verifier_0( t, $E.2, ch_prop ) @ #j)" in line and "#j. (InvalidChallenge( $E.2, C, t ) @ #j)" in line:
            l3.append(num)

        elif "!KU( pk(~enclave_ltk) )" in line:
            l20.append(num)

        elif "!KU( sign(<$E.2, pk(~enclave_ltk)>, ~ltk.1) ) @ #vk.15" in line:
            l4.append(num)

        elif "OUT_Verifier_0( t, $E.3, ch_prop ) @ #j)" in line and "(#j < #vr.17))" in line and "(InvalidChallenge( $E.3, C, t ) @ #j)" in line:
            l5.append(num)

        elif "!KU( aenc(hint, pk(~enclave_ltk)) ) @ #vk.4" in line:
            l5.append(num)

        elif "!KU( aenc(hint, pk(~enclave_ltk)) ) @ #vk.3" in line:
            l5.append(num)

# TODO: Binding integrity is broken again... sigh
        elif "Client_2( $C.1, $E.4, ~ltk.1, $A.3, server_pk.1" in line:
            l6.append(num)

        elif "OUT_Verifier_0( t, $E.1, ch_prop ) @ #j)" in line and "(InvalidChallenge( $E.1, C, t ) @ #j)" in line:
            l6.append(num)

        elif "OUT_Verifier_0( t, $E.3, ch_prop ) @ #j)" in line and "(InvalidChallenge( $E.3, C, t ) @ #j)" in line:
            l6.append(num)

        elif "!KU( ~ltk.1 ) @ #vk.17" in line:
            l7.append(num)

        elif "Client_2( $C.1, $E.5, ~ltk.1, $A.4, server_pk.2 )" in line and "#vr.25" in line:
            l7.append(num)

        elif "!KU( sign(<$E.1, pk(~enclave_ltk)>, ~ltk.1) ) @ #vk.24" in line:
            l7.append(num)

        elif "!KU( pk(~enclave_ltk) ) @ #vk.19" in line:
            l7.append(num)

        elif "!KU( sign(<$E.1, pk(~enclave_ltk)>, ~ltk.1)" in line:
            l7.append(num)

        elif "!KU( ~ltk.1 ) @ #vk.21" in line:
            l7.append(num)

        elif "!KU( sign(<$E.1, pk(~enclave_ltk)>, ~ltk)" in line:
            l7.append(num)

        elif "Client_2( $C.1, $E.5, ~ltk.1, $A.4, server_pk.2 )" in line and "#vr.27" in line:
            l8.append(num)

        elif "!KU( ~ltk.1 )" in line:
            l8.append(num)

#        elif "!KU( ~ltk.1 ) @ #vk.20" in line:
#            l8.append(num)

#        elif "!KU( ~ltk.1 ) @ #vk.19" in line:
#            l8.append(num)

        elif "OUT_Verifier_0( t, $E.3, ch_prop ) @ #j)" in line and "(#j < #vr.19))" in line and "(InvalidChallenge( $E.3, C, t )" in line:
            l9.append(num)

        elif "Client_2( $C.2, $E.3, ~ltk.1, $A.2, server_pk" in line:
            l9.append(num)

        elif "Client_2( $C.2, $E.4, ~ltk.1, $A.2, server_pk.1" in line:
            l9.append(num)

        elif "Client_2( $C.2, $E.5, ~ltk.1, $A.3, server_pk.2" in line:
            l9.append(num)

        elif "Client_2( $C.2, $E.3, ~ltk.1, $A.1, server_pk" in line:
            l9.append(num)

        elif re.search(client_2_regex, line):
            l9.append(num)

        elif "Enclave_0( $E.3, $C.3, ~agent_id.1, ~n_0.1, ~ltk.1" in line:
            l9.append(num)

        elif "Enclave_0( $E.2, $C.3, ~agent_id.1, ~n_0.1, ~ltk.1" in line:
            l9.append(num)

        elif "(#vl.2, 0) ~~> (#vk.3, 0)" in line:
            l10.append(num)

        elif "(#vl.1, 0) ~~> (#vk.3, 0)" in line:
            l10.append(num)

        elif "!KU( ~enclave_ltk ) @ #vk.26" in line:
            l10.append(num)

        elif "(#vl.1, 0) ~~> (#vk.2, 0)" in line:
            l10.append(num)

        elif "!KU( ~enclave_ltk ) @ #vk.21" in line:
            l12.append(num)

        elif "Verifier_0( $V, ~ch_prop, ~hint.1, $A, ~ltk.1" in line:
            l11.append(num)

        elif "Client_2(" in line:
            l1.append(num)

        elif "Client_2( ~ctid.1, eid.1, $C.1, $E.3, ~agent_id.2, $A.2" in line:
            l2.append(num)

#        elif "Client_2( ~ctid.1, eid.1, $C.1, $E.3, ~agent_id.2, $A.2" in line:
#            l3.append(num)

        elif "Client_2( $C.1, $E.4, ~enclave_ltk, $A.2, server_pk.1" in line:
            l11.append(num)

        elif "OUT_Verifier_0( t, $E.5, ch_prop ) @ #j)" in line and "(#j < #vr.32))" in line and "(InvalidChallenge( $E.5, C, t ) @ #j)" in line:
            l12.append(num)

        elif "Verifier_0( $V, ~ch_prop, ~enclave_ltk, $A, ~ltk.2" in line:
            l12.append(num)

        elif "!KU( pk(~enclave_ltk) ) @ #vk.8" in line:
            l13.append(num)

        elif "!KU( pk(~enclave_ltk) ) @ #vk.23" in line:
            l13.append(num)

        elif "!KU( ~enclave_ltk ) @ #vk.18" in line:
            l14.append(num)

        elif "!KU( ~ltk.1 ) @ #vk.24" in line:
            l14.append(num)

        elif "Client_2( $C.1, $E.4, ~enclave_ltk, $A.3, server_pk.1" in line:
            l15.append(num)

        elif "(#vl.2, 0) ~~> (#vk.5, 0)" in line:
            l15.append(num)

        elif "(OUT_Verifier_0( t, $E.5, ch_prop ) @ #j)" in line and "(#j < #vr.30))" in line and "(InvalidChallenge( $E.5, C, t ) @ #j)" in line:
            l16.append(num)

        elif "(#vl.1, 0) ~~> (#vk.5, 0)" in line:
            l17.append(num)

        elif "OUT_Verifier_0( t, $E.4, ch_prop ) @ #j)" in line and "(InvalidChallenge( $E.4, C, t ) @ #j)" in line:
            l18.append(num)

        elif "Client_2( $C.1, $E.5, ~enclave_ltk, $A.4, server_pk.2" in line:
            l19.append(num)

        elif "(#vl.1, 0) ~~> (#vk.4, 0)" in line:
            l20.append(num)

        pass
    else:
        exit(0)


ranked = l1 + l2 + l3 + l4 + l5 + l6 + l7 + l8 + l9 + l10 + l11 + l12 + l13 + l14 + l15 + l16 + l17 + l18 + l19 + l20


#if len(ranked) == 0 and len(lines) > 0:
#    error =
#    with open('pomoc.txt', 'w') as f:
#        f.write(str(lines))
#    raise Exception('Oracle found no good choice')

for i in ranked:
    print(i)



    """
        elif "!KU( sign(<$E, pk(x)>, ~ltk.1)" in line:
            l2.append(num)

        elif "!KU( ~ltk.1 ) @ #vk.15" in line:
            l2.append(num)

        elif " ~ltk.1, $" in line or " ~ltk.1, pk" in line:
            l3.append(num)

        elif "!KU( pk(~enclave_ltk)" in line:
            l3.append(num)

#        elif "!KU( ~enclave_ltk ) @ #vk.14" in line or "!KU( ~enclave_ltk ) @ #vk.30" in line or "!KU( ~enclave_ltk ) @ #vk.32" in line or "!KU( ~enclave_ltk ) @ #vk.37" in line or "!KU( ~enclave_ltk ) @ #vk.39" in line or "!KU( ~enclave_ltk ) @ #vk.24" in line or "!KU( ~enclave_ltk ) @ #vk.26" in line or "!KU( ~enclave_ltk ) @ #vk.31" in line or "!KU( ~enclave_ltk ) @ #vk.33" in line or "!KU( ~enclave_ltk ) @ #vk.28" in line or "!KU( ~enclave_ltk ) @ #vk.35" in line:
#            l3.append(num)

        elif "!KU( ~enclave_ltk )" in line:
            l3.append(num)

        elif " ~enclave_ltk, $" in line or " ~enclave_ltk, pk" in line:
            l3.append(num)

        elif "@ #j))" in line:
            l3.append(num)

        elif "∥" in line:
            l3.append(num)

        elif "senc(sign(h1(~ch_prop, '0', 'g'^" in line:
            l4.append(num)

        elif "!KU( senc(sign(<" in line and "<~n_0.1" in line:
            l4.append(num)

        elif "sign(h1(~ch_prop, '0', 'g'^" in line:
            l4.append(num)

        elif "!KU( aenc(~hint, pk(~enclave_ltk" in line:
            l6.append(num)

        elif "!KU( sign(<" in line and "<~n_0.1" in line:
            l5.append(num)

        elif "!KU( ~n_0 ) @ #vk.12" in line or "!KU( ~n_0 ) @ #vk.18" in line:
            l5.append(num)

        elif "Enclave_3(" in line:
            l6.append(num)

        elif " ~n_0, $" in line:
            l6.append(num)

#        elif "!KU( ~ch_pos ) @ #vk.18" in line or "!KU( ~ch_pos ) @ #vk.17" in line:
#            l4.append(num)

#        elif "!KU( ~ch_pos ) @ #vk.15" in line or "!KU( ~ch_pos ) @ #vk.22" in line or "!KU( ~ch_pos ) @ #vk.25" in line or "!KU( ~ch_pos ) @ #vk.20" in line or "!KU( ~ch_pos ) @ #vk.24" in line:
#            l5.append(num)

        elif "!KU( ~hint )" in line:
            l7.append(num)

        elif "Enclave_0( $E, $C.1, ~agent_id.1, ~n_0, ~x_0, pk(x)" in line and "#vr.19" in line:
            l5.append(num)

        elif " ~hint, $" in line or " ~hint, pk" in line:
            l6.append(num)

#        if " ~enclave_ltk, $" in line or " ~enclave_ltk, pk" in line:
#            l6.append(num)

        elif "!KU( ~enclave_ltk ) @ #vk.18" in line or "!KU( ~enclave_ltk ) @ #vk.17" in line:
            l6.append(num)

        elif "Enclave_0( $E, $C.1, ~agent_id, ~n_0, ~x_0, pk(x)" in line and "#vr.18" in line:
            l7.append(num)

        elif "Enclave_0( $E, $C.1, ~agent_id, ~n_0, ~x_0, pk(x)" in line and "#vr.17" in line:
            l7.append(num)

        elif "Enclave_0( $E, $C.1, ~agent_id.1, ~n_0, ~x_0, pk(x)" in line and "#vr.18" in line:
            l7.append(num)

        elif "!KU( h1(~ch_prop, '0', z.1, ~hint, X_0, n_0," in line and "#vk.16" in line:
            l8.append(num)
"""
