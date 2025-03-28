firewall {
    family inet {
        /*
         ** $Id:$
         ** $Date:$
         ** $Revision:$
         **
         ** Juniper policy for overlap case.
         */
        replace: filter SamplePolicy {
            interface-specific;
            term accept-web-services {
                from {
                    source-address {
                        1.2.3.0/24;
                        10.1.1.0/24;
                        10.2.2.0/24;
                        10.3.3.0/24;
                        10.4.4.0/24;
                        10.5.5.0/24;
                        10.6.6.0/24;
                        10.7.7.0/24;
                        10.8.8.0/24;
                        10.9.9.0/24;
                    }
                    destination-address {
                        1.0.0.0/8;
                        8.8.8.8/32;
                        11.1.1.0/24;
                        11.2.2.0/24;
                        11.3.3.0/24;
                        11.4.4.0/24;
                        11.5.5.0/24;
                        11.6.6.0/24;
                        11.7.7.0/24;
                        11.8.8.0/24;
                    }
                    destination-port [ 80 443 ];
                    protocol tcp;
                }
                then accept;
            }
            term accept-ssh {
                from {
                    source-address {
                        1.2.3.0/24;
                        10.2.2.0/24;
                        10.4.4.0/24;
                        10.6.6.0/24;
                        10.8.8.0/24;
                    }
                    destination-address {
                        8.8.8.8/32;
                        11.2.2.0/24;
                        11.4.4.0/24;
                        11.6.6.0/24;
                        11.8.8.0/24;
                    }
                    destination-port 22;
                    protocol tcp;
                }
                then accept;
            }
        }
    }
}
