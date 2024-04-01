use super::*;

impl Interface {
    pub(crate) fn mld_egress<D>(&mut self, device: &mut D) -> bool
    where
        D: Device + ?Sized,
    {
        match self.inner.mld_report_state {
            MldReportState::ToSpecificQuery { timeout, address } if self.inner.now >= timeout => {
                let mut buffer = [0u8; 20];

                if let Some(pkt) = self.inner.mldv2_listener_join_packet(address, &mut buffer) {
                    // Send initial membership report
                    if let Some(tx_token) = device.transmit(self.inner.now) {
                        // NOTE(unwrap): packet destination is multicast, which is always routable and doesn't require neighbor discovery.
                        self.inner
                            .dispatch_ip(tx_token, PacketMeta::default(), pkt, &mut self.fragmenter)
                            .unwrap();
                    } else {
                        return false;
                    }
                }

                self.inner.mld_report_state = MldReportState::Inactive;
                true
            }
            MldReportState::ToGeneralQuery {
                timeout,
                interval,
                next_index,
            } if self.inner.now >= timeout => {
                let addr = self
                    .inner
                    .ipv6_multicast_groups
                    .iter()
                    .nth(next_index)
                    .map(|(addr, ())| *addr);
                let mut buffer = [0u8; 20];

                match addr {
                    Some(addr) => {
                        if let Some(pkt) = self.inner.mldv2_listener_join_packet(addr, &mut buffer)
                        {
                            // Send initial membership report
                            if let Some(tx_token) = device.transmit(self.inner.now) {
                                // NOTE(unwrap): packet destination is multicast, which is always routable and doesn't require neighbor discovery.
                                self.inner
                                    .dispatch_ip(
                                        tx_token,
                                        PacketMeta::default(),
                                        pkt,
                                        &mut self.fragmenter,
                                    )
                                    .unwrap();
                            } else {
                                return false;
                            }
                        }

                        let next_timeout = (timeout + interval).max(self.inner.now);
                        self.inner.mld_report_state = MldReportState::ToGeneralQuery {
                            timeout: next_timeout,
                            interval,
                            next_index: next_index + 1,
                        };

                        true
                    }

                    None => {
                        self.inner.mld_report_state = MldReportState::Inactive;
                        false
                    }
                }
            }
            _ => false,
        }
    }
}

impl InterfaceInner {
    pub(super) fn process_mld<'frame>(&mut self, mld_repr: MldRepr) -> Option<Packet<'frame>> {
        match mld_repr {
            MldRepr::Query {
                mcast_addr,
                num_srcs,
                ..
            } if mcast_addr.is_unspecified() && num_srcs == 0 => {
                // General Query
                let max_response_delay = mld_repr.max_response_delay().unwrap();
                let interval = max_response_delay / (self.ipv6_multicast_groups.len() as u32 + 1);

                self.mld_report_state = MldReportState::ToGeneralQuery {
                    timeout: self.now + interval,
                    interval,
                    next_index: 0,
                };
            }
            MldRepr::Query {
                mcast_addr,
                num_srcs,
                ..
            } if num_srcs == 0 => {
                // Multicast Address Specific Query
                let max_response_delay = mld_repr.max_response_delay().unwrap();

                self.mld_report_state = MldReportState::ToSpecificQuery {
                    timeout: self.now + (max_response_delay / 4),
                    address: mcast_addr,
                };
            }
            MldRepr::Query { .. } => {
                // Multicast Address and Source Specific Query
            }
            _ => (),
        };

        None
    }
}
