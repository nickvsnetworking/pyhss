def generate_lte_auth_vector(self, imsi, plmn):
        """
        Returns the lte auth vector for the subscriber by querying the store
        for the crypto algo and secret keys.
        """
        sid = SIDUtils.to_str(SubscriberID(id=imsi, type=SubscriberID.IMSI))
        subs = self._store.get_subscriber_data(sid)

        if subs.lte.state != LTESubscription.ACTIVE:
            raise CryptoError("LTE service not active for %s" % sid)

        if subs.lte.auth_algo != LTESubscription.MILENAGE:
            raise CryptoError("Unknown crypto (%s) for %s" %
                              (subs.lte.auth_algo, sid))

        if len(subs.lte.auth_key) != 16:
            raise CryptoError("Subscriber key not valid for %s" % sid)

        if len(subs.lte.auth_opc) == 0:
            opc = Milenage.generate_opc(subs.lte.auth_key, self._op)
        elif len(subs.lte.auth_opc) != 16:
            raise CryptoError("Subscriber OPc is invalid length for %s" % sid)
        else:
            opc = subs.lte.auth_opc

        sqn = self.seq_to_sqn(self.get_next_lte_auth_seq(imsi))
        milenage = Milenage(self._amf)
        return milenage.generate_eutran_vector(subs.lte.auth_key,
opc, sqn, plmn) 
