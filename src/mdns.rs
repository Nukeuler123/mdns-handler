use anyhow::{Error, Result};
use std::net::{IpAddr, Ipv4Addr, UdpSocket};

#[cfg(not(target_os = "windows"))]
use net2::unix::UnixUdpBuilderExt;
use simple_dns::rdata::{RData, A};
use simple_dns::QTYPE::PTR;
use simple_dns::{Name, Packet, Question, ResourceRecord, CLASS, QCLASS};
use std::net::SocketAddr;
use std::time::Duration;

/// The IP address for the mDNS multicast socket.
const MULTICAST_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MULTICAST_PORT: u16 = 5353;
const ADDR_ANY: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 0);

pub struct MdnsHandler {
    service_name: String,
    socket: UdpSocket,
}

impl MdnsHandler {
    pub fn new(service: String) -> Result<Self> {
        //Creates a socket and joins it to the mdns multicast address
        let socket = create_socket()?;
        socket.set_multicast_loop_v4(false)?;
        socket.join_multicast_v4(&MULTICAST_ADDR, &ADDR_ANY)?;
        socket.set_read_timeout(Option::from(Duration::from_millis(10)))?;

        Ok(Self {
            service_name: service,
            socket,
        })
    }
}

impl MdnsHandler {
    pub fn send_multicast_search(&self) -> Result<()> {
        // Create a new mdns query with the service name we're looking for, then turn it into bytes
        let mut packet = Packet::new_query(0, false);
        packet.questions.push(Question::new(
            Name::new(&self.service_name)?,
            PTR,
            QCLASS::IN,
            false,
        ));
        let packet = packet.build_bytes_vec()?;

        //This is where the magic happens, create a SocketAddr with the multicast address and port
        //Then simply send the packet to that address, this basically broadcasts it on the standard
        //Mdns multicast address and port for any and all systems to hear
        let addr = SocketAddr::new(MULTICAST_ADDR.into(), MULTICAST_PORT);
        self.socket.send_to(&packet, addr)?;

        Ok(())
    }

    pub fn check_mdns(&self) -> Result<Option<IpAddr>> {
        //Create a buffer and try to receive information
        let mut buf: [u8; 4096] = [0; 4096];
        let recv_info = self.socket.recv_from(&mut buf)?;

        let parse = Packet::parse(&buf)?;
        if let Some(quest) = parse.questions.get(0) {
            return if &quest.qname.to_string() == &self.service_name {
                //If we get a Mdns packet asking for our service, create a reply
                let mut builder = Packet::new_reply(0);
                builder.answers.push(ResourceRecord::new(
                    Name::new(&self.service_name)?,
                    CLASS::IN,
                    0,
                    RData::A(A { address: 0 }), //TODO put the local system's address here
                ));
                let packet = builder.build_bytes_vec()?;

                //Send response directly to sender before sending the IP up the chain
                self.socket.send_to(&packet, recv_info.1)?;
                Ok(Some(recv_info.1.ip()))
            } else {
                //Just here for debug reasons, means we got Mdns that aint for us
                Err(Error::msg("Unrelated mdns"))
            };
        }
        //Someone responded to our search, send their IP up the chain
        if parse.answers.get(0).is_some() {
            return Ok(Some(recv_info.1.ip()));
        }
        Ok(None)
    }
}

#[cfg(not(target_os = "windows"))]
fn create_socket() -> Result<UdpSocket> {
    Ok(net2::UdpBuilder::new_v4()?
        .reuse_address(true)?
        .reuse_port(true)?
        .bind((ADDR_ANY, MULTICAST_PORT))?)
}

#[cfg(target_os = "windows")]
fn create_socket() -> Result<UdpSocket> {
    Ok(net2::UdpBuilder::new_v4()?
        .reuse_address(true)?
        .bind((ADDR_ANY, MULTICAST_PORT))?)
}