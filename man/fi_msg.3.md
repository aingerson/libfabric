---
layout: page
title: fi_msg(3)
tagline: Libfabric Programmer's Manual
---
{% include JB/setup %}

# NAME

fi_msg - Message data transfer operations

fi_recv / fi_recvv / fi_recvmsg
:   Post a buffer to receive an incoming message

fi_send / fi_sendv / fi_sendmsg
fi_inject / fi_senddata
:   Initiate an operation to send a message

# SYNOPSIS

```c
#include <rdma/fi_endpoint.h>

ssize_t fi_recv(struct fid_ep *ep, void * buf, size_t len,
	void *desc, fi_addr_t src_addr, void *context);

ssize_t fi_recvv(struct fid_ep *ep, const struct iovec *iov, void **desc,
	size_t count, fi_addr_t src_addr, void *context);

ssize_t fi_recvmsg(struct fid_ep *ep, const struct fi_msg *msg,
	uint64_t flags);

ssize_t fi_send(struct fid_ep *ep, const void *buf, size_t len,
	void *desc, fi_addr_t dest_addr, void *context);

ssize_t fi_sendv(struct fid_ep *ep, const struct iovec *iov,
	void **desc, size_t count, fi_addr_t dest_addr, void *context);

ssize_t fi_sendmsg(struct fid_ep *ep, const struct fi_msg *msg,
	uint64_t flags);

ssize_t fi_inject(struct fid_ep *ep, const void *buf, size_t len,
	fi_addr_t dest_addr);

ssize_t fi_senddata(struct fid_ep *ep, const void *buf, size_t len,
	void *desc, uint64_t data, fi_addr_t dest_addr, void *context);

ssize_t fi_injectdata(struct fid_ep *ep, const void *buf, size_t len,
	uint64_t data, fi_addr_t dest_addr);
```

# ARGUMENTS

*ep*
: Fabric endpoint on which to initiate send or post receive buffer.

*buf*
: Data buffer to send or receive.

*len*
: Length of data buffer to send or receive, specified in bytes.  Valid
  transfers are from 0 bytes up to the endpoint's max_msg_size.

*iov*
: Vectored data buffer.

*count*
: Count of vectored data entries.

*desc*
: Descriptor associated with the data buffer.  See [`fi_mr`(3)](fi_mr.3.html).

*data*
: Remote CQ data to transfer with the sent message.

*dest_addr*
: Destination address for connectionless transfers.  Ignored for
  connected endpoints.

*src_addr*
: Applies only to connectionless endpoints configured with the FI_DIRECTED_RECV.
  For all other endpoint configurations, src_addr is ignored. src_addr defines
  the source address to receive from. By default, the src_addr is treated as a
  source endpoint address (i.e. fi_addr_t returned from fi_av_insert /
  fi_av_insertsvc / fi_av_remove). If the FI_AUTH_KEY flag is specified with
  fi_recvmsg, src_addr is treated as a source authorization key (i.e. fi_addr_t
  returned from fi_av_insert_auth_key). If set to FI_ADDR_UNSPEC, any source
  address may match.

*msg*
: Message descriptor for send and receive operations.

*flags*
: Additional flags to apply for the send or receive operation.

*context*
: User specified pointer to associate with the operation.  This parameter is
  ignored if the operation will not generate a successful completion, unless
  an op flag specifies the context parameter be used for required input.

# DESCRIPTION

The send functions -- fi_send, fi_sendv, fi_sendmsg,
fi_inject, and fi_senddata -- are used to
transmit a message from one endpoint to another endpoint.  The main
difference between send functions are the number and type of
parameters that they accept as input.  Otherwise, they perform the
same general function.  Messages sent using fi_msg operations are
received by a remote endpoint into a buffer posted to receive such
messages.

The receive functions -- fi_recv, fi_recvv, fi_recvmsg --
post a data buffer to an endpoint to receive inbound messages.
Similar to the send operations, receive operations operate
asynchronously.  Users should not touch the posted data buffer(s)
until the receive operation has completed.

An endpoint must be enabled before an application can post send
or receive operations to it.  For connected endpoints, receive
buffers may be posted prior to connect or accept being called on
the endpoint.  This ensures that buffers are available to receive
incoming data immediately after the connection has been established.

Completed message operations are reported to the user through one or
more event collectors associated with the endpoint.  Users provide
context which are associated with each operation, and is returned to
the user as part of the event completion.  See fi_cq for completion
event details.

## fi_send

The call fi_send transfers the data contained in the user-specified
data buffer to a remote endpoint, with message boundaries being
maintained.

## fi_sendv

The fi_sendv call adds support for a scatter-gather list to fi_send.
The fi_sendv transfers the set of data buffers
referenced by the iov parameter to a remote endpoint as a single
message.

## fi_sendmsg

The fi_sendmsg call supports data transfers over both connected and
connectionless endpoints, with the ability to control the send operation
per call through the use of flags.  The fi_sendmsg function takes a
`struct fi_msg` as input.

```c
struct fi_msg {
	const struct iovec *msg_iov; /* scatter-gather array */
	void               **desc;   /* local request descriptors */
	size_t             iov_count;/* # elements in iov */
	fi_addr_t          addr;     /* optional endpoint address */
	void               *context; /* user-defined context */
	uint64_t           data;     /* optional message data */
};
```

## fi_inject

The send inject call is an optimized version of fi_send with the
following characteristics.  The data buffer is available for reuse
immediately on return from the call, and no CQ entry will be written
if the transfer completes successfully.

Conceptually, this means that the fi_inject function behaves as if
the FI_INJECT transfer flag were set, selective completions are enabled,
and the FI_COMPLETION flag is not specified.  Note that the CQ entry
will be suppressed even if the default behavior of the endpoint is
to write CQ entries for all successful completions.  See the flags
discussion below for more details. The requested message size that
can be used with fi_inject is limited by inject_size.

If FI_HMEM is enabled, the fi_inject call can only accept buffer with
iface equal to FI_HMEM_SYSTEM if the provider requires the FI_MR_HMEM
mr_mode.  This limitation applies to all the fi_\*inject\* calls and
does not affect how inject_size is reported.

## fi_senddata

The send data call is similar to fi_send, but allows for the sending
of remote CQ data (see FI_REMOTE_CQ_DATA flag) as part of the
transfer.

## fi_injectdata

The inject data call is similar to fi_inject, but allows for the sending
of remote CQ data (see FI_REMOTE_CQ_DATA flag) as part of the
transfer.

## fi_recv

The fi_recv call posts a data buffer to the receive queue of the
corresponding endpoint.  Posted receives are searched in the order in
which they were posted in order to match sends.
Message boundaries are maintained.  The order in which
the receives complete is dependent on
the endpoint type and protocol.  For connectionless endpoints, the
src_addr parameter can be used to indicate that a buffer should be
posted to receive incoming data from a specific remote endpoint.

## fi_recvv

The fi_recvv call adds support for a scatter-gather list to fi_recv.
The fi_recvv posts the set of data buffers referenced by the iov
parameter to a receive incoming data.

## fi_recvmsg

The fi_recvmsg call supports posting buffers over both connected and
connectionless endpoints, with the ability to control the receive
operation per call through the use of flags.  The fi_recvmsg function
takes a struct fi_msg as input.

# FLAGS

The fi_recvmsg and fi_sendmsg calls allow the user to specify flags
which can change the default message handling of the endpoint.  Flags
specified with fi_recvmsg / fi_sendmsg override most flags previously
configured with the endpoint, except where noted (see fi_endpoint.3).
The following list of flags are usable with fi_recvmsg and/or
fi_sendmsg.

*FI_REMOTE_CQ_DATA*
: Applies to fi_sendmsg.  Indicates that remote CQ data is available
  and should be sent as part of the request.  See fi_getinfo for
  additional details on FI_REMOTE_CQ_DATA.  This flag is implicitly
  set for fi_senddata and fi_injectdata.

*FI_COMPLETION*
: Indicates that a completion entry should be generated for the
  specified operation.  The endpoint must be bound to a completion
  queue with FI_SELECTIVE_COMPLETION that corresponds to the
  specified operation, or this flag is ignored.

*FI_MORE*
: Indicates that the user has additional requests that will
  immediately be posted after the current call returns.  Use of this
  flag may improve performance by enabling the provider to optimize
  its access to the fabric hardware.

*FI_INJECT*
: Applies to fi_sendmsg.  Indicates that the outbound data buffer
  should be returned to user immediately after the send call returns,
  even if the operation is handled asynchronously.  This may require
  that the underlying provider implementation copy the data into a
  local buffer and transfer out of that buffer. This flag can only
  be used with messages smaller than inject_size.

*FI_MULTI_RECV*
: Applies to posted receive operations.  This flag allows the user to
  post a single buffer that will receive multiple incoming messages.
  Received messages will be packed into the receive buffer until the
  buffer has been consumed.  Use of this flag may cause a single
  posted receive operation to generate multiple events as messages are
  placed into the buffer.  The placement of received data into the
  buffer may be subjected to provider specific alignment restrictions.

  The buffer will be released by the provider when the available buffer
  space falls below the specified minimum (see FI_OPT_MIN_MULTI_RECV).
  Note that an entry to the associated receive completion queue will
  always be generated when the buffer has been consumed, even if other
  receive completions have been suppressed (i.e. the Rx context has been
  configured for FI_SELECTIVE_COMPLETION).  See the FI_MULTI_RECV
  completion flag [`fi_cq`(3)](fi_cq.3.html).

*FI_INJECT_COMPLETE*
: Applies to fi_sendmsg.  Indicates that a completion should be
  generated when the source buffer(s) may be reused.

*FI_TRANSMIT_COMPLETE*
: Applies to fi_sendmsg and fi_recvmsg.  For sends, indicates that a
  completion should not be generated until the operation has been
  successfully transmitted and is no longer being tracked by the provider.
  For receive operations, indicates that a completion may be generated
  as soon as the message has been processed by the local provider,
  even if the message data may not be visible to all processing
  elements.  See [`fi_cq`(3)](fi_cq.3.html) for target side completion
  semantics.

*FI_DELIVERY_COMPLETE*
: Applies to fi_sendmsg.  Indicates that a completion should be
  generated when the operation has been processed by the destination.

*FI_FENCE*
: Applies to transmits.  Indicates that the requested operation, also
  known as the fenced operation, and any operation posted after the
  fenced operation will be deferred until all previous operations
  targeting the same peer endpoint have completed.  Operations posted
  after the fencing will see and/or replace the results of any
  operations initiated prior to the fenced operation.

  The ordering of operations starting at the posting of the fenced
  operation (inclusive) to the posting of a subsequent fenced operation
  (exclusive) is controlled by the endpoint's ordering semantics.

*FI_MULTICAST*
: Applies to transmits.  This flag indicates that the address specified
  as the data transfer destination is a multicast address.  This flag must
  be used in all multicast transfers, in conjunction with a multicast
  fi_addr_t.

*FI_AUTH_KEY*
: Only valid with domains configured with FI_AV_AUTH_KEY and connectionless
  endpoints configured with FI_DIRECTED_RECV. When used with fi_recvmsg, this
  flag denotes that the src_addr is an authorization key fi_addr_t instead of
  an endpoint fi_addr_t.

# NOTES

If an endpoint has been configured with FI_MSG_PREFIX, the application
must include buffer space of size msg_prefix_size, as specified by the
endpoint attributes.  The prefix buffer must occur at the start of the
data referenced by the buf parameter, or be referenced by the first IO vector.
Message prefix space cannot be split between multiple IO vectors.  The size
of the prefix buffer should be included as part of the total buffer length.

# RETURN VALUE

Returns 0 on success. On error, a negative value corresponding to fabric
errno is returned. Fabric errno values are defined in
`rdma/fi_errno.h`.

See the discussion below for details handling FI_EAGAIN.

# ERRORS

*-FI_EAGAIN*
: Indicates that the underlying provider currently lacks the resources
  needed to initiate the requested operation.  The reasons for a provider
  returning FI_EAGAIN are varied.  However, common reasons include
  insufficient internal buffering or full processing queues.

  Insufficient internal buffering is often associated with operations that
  use FI_INJECT.  In such cases, additional buffering may become available as
  posted operations complete.

  Full processing queues may be a temporary state related to local
  processing (for example, a large message is being transferred), or may be
  the result of flow control.  In the latter case, the queues may remain
  blocked until additional resources are made available at the remote side
  of the transfer.

  In all cases, the operation may be retried after additional resources become
  available.  When using FI_PROGRESS_MANUAL, the application must check for
  transmit and receive completions after receiving FI_EAGAIN as a return value,
  independent of the operation which failed.  This is also strongly recommended
  when using FI_PROGRESS_AUTO, as acknowledgements or flow control messages may
  need to be processed in order to resume execution.

# SEE ALSO

[`fi_getinfo`(3)](fi_getinfo.3.html),
[`fi_endpoint`(3)](fi_endpoint.3.html),
[`fi_domain`(3)](fi_domain.3.html),
[`fi_cq`(3)](fi_cq.3.html)
