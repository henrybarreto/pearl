use std::{
    pin::Pin,
    task::{Context, Poll},
};

use futures::StreamExt;

use tokio::{
    io::{self, AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};

use tracing::trace;

use websocket::{
    protocol::frame::{
        coding::{Data, OpCode},
        Frame,
    },
    Bytes, Message,
};

use websocket_async::{MaybeTlsStream, WebSocketStream};

/// It is an adapter to convert websocket connection's messages into SSH packets to the SSH stream.
///
/// Essentially, it reads data from websocket, remove from the Message's packet and put back to the
/// SSH stream. It also does the same when the data goes out the SSH server, wrapping it into a
/// websocket binary message. Check the implementation for more details.
pub struct Adapter {
    /// Internal websocket stream.
    stream: WebSocketStream<MaybeTlsStream<TcpStream>>,
    /// Internal buffer to the remaining bytes of an SSH packet after reading the packet size.
    buffer: Option<Bytes>,
}

impl Adapter {
    pub fn new(stream: WebSocketStream<MaybeTlsStream<TcpStream>>) -> Self {
        return Adapter {
            stream,
            buffer: None,
        };
    }
}

impl AsyncRead for Adapter {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        trace!("poll_read called on websocket to ssh adapter");

        // NOTE: It checks if there is a pending buffer to be written. If it does, remove the
        // buffer from structure, letting `None` on its place, and write it to SSH stream. Normally
        // it is called after the SSH packet size reading, to read the content of the packet.
        if let Some(buffer) = self.buffer.take() {
            trace!("there is some data on buffer to be read to SSH");

            buf.put_slice(&buffer);

            return Poll::Ready(Ok(()));
        }

        return match self.stream.poll_next_unpin(cx) {
            Poll::Ready(option) => {
                trace!("poll ready on websocket read");

                // TODO: Remove `unwrap` calls.
                let p = option.unwrap();
                let msg = p.unwrap();

                match msg {
                    Message::Binary(buffer) => {
                        // NOTE: The SSH crate that we're using, cannot deal with a full WebSocket
                        // binary packet at once because it first reads four bytes, the SSH packet size,
                        // and, after that, the remaining, the size read. To address this issue, we
                        // check if the space on the buffer is less than the data inside the
                        // message, sending only the required piece and storing the remaining to
                        // the next read in a buffer on the adapter structure.
                        if buf.remaining() < buffer.len() {
                            // WARN: The `remaining` is a variable because after put the data into
                            // the slice, its value goes to zero, messing up with the remaining
                            // part put on structure's buffer.
                            let remaining = buf.remaining();

                            buf.put_slice(&buffer[..remaining]);

                            self.buffer = Some(buffer.slice(remaining..));
                        } else {
                            buf.put_slice(&buffer);
                        }
                    }
                    // TODO: Deal better with all cases of messages.
                    Message::Close(e) => {
                        println!("{:?}", e.unwrap());
                    }
                    _ => panic!("other message than binary"),
                }

                Poll::Ready(Ok(()))
            }
            Poll::Pending => {
                trace!("poll pending on websocket read");

                Poll::Pending
            }
        };
    }
}

impl AsyncWrite for Adapter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        trace!("WRITE");

        let mut frame = Frame::message(buf.to_vec(), OpCode::Data(Data::Binary), true);
        // WARN: Avoid "bad mask" error when creating the frame.
        // TODO: Create the mask the right way.
        frame.header_mut().mask = Some([1, 2, 3, 4]);

        let mut serialized = Vec::new();

        // NOTE: After creating the frame, we put it into a slice to be written into the websocket
        // connection.
        frame.format(&mut serialized).unwrap();

        // NOTE: After converting the SSH packet into a websocket frame, we write it to the
        // websocket connection, confirming the size of the SSH packet to caller, not what was
        // written on websocket connection, as it greater than the SSH packet.
        return match Pin::new(&mut self.get_mut().stream.get_mut()).poll_write(cx, &serialized) {
            Poll::Ready(_) => Poll::Ready(Ok(buf.len())),
            Poll::Pending => {
                trace!("poll pending on websocket write");

                Poll::Pending
            }
        };
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        trace!("FLUSH");

        Pin::new(&mut self.get_mut().stream.get_mut()).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        trace!("SHUTDOWN");

        Pin::new(&mut self.get_mut().stream.get_mut()).poll_shutdown(cx)
    }
}
