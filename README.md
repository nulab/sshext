# sshext

Implements OpenSSH's deviations and extensions to the published SSH protocol.

## Requires

Go 1.18+

## Installation

This package can be installed with the go get command:

```
$ go get -u github.com/nulab/sshext
```

## Support

* [x] hostkeys-00@openssh.com, hostkeys-prove-00@openssh.com
* [x] no-more-sessions@openssh.com

## Usage

```go
sconn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
if err != nil {
    return
}

// Handle hostkeys-00@openssh.com and hostkeys-prove-00@openssh.com
reqs, err = sshext.UpdateHostKeys(sconn, reqs, signers)
// Handle no-more-sessions@openssh.com
reqs, noMore, err = sshext.NoMoreSessions(reqs)

go ssh.DiscardRequests(reqs)

for c := range chans {
    if c.ChannelType() == "session" {
        select {
        case <-noMore:
            sconn.Close()
        default:
            // handle session channel
        }
    }
}
```

## References

* https://github.com/openssh/openssh-portable/blob/master/PROTOCOL
* https://man7.org/linux/man-pages/man5/ssh_config.5.html 
* https://www.openssh.com/txt/release-8.5

## Bugs and Feedback

For bugs, questions and discussions please use the GitHub Issues.

## License

[MIT License](http://www.opensource.org/licenses/mit-license.php)
