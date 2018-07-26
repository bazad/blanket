blanket
===================================================================================================

<!-- Brandon Azad -->

Blanket is a sandbox escape targeting iOS 11.2.6, although the main vulnerability was only patched
in iOS 11.4.1. It exploits a Mach port replacement vulnerability in launchd (CVE-2018-4280), as
well as several smaller vulnerabilities in other services, to execute code inside the ReportCrash
process, which is unsandboxed, runs as root, and has the `task_for_pid-allow` entitlement. This
grants blanket control over every process running on the phone, including security-critical ones
like amfid.

The exploit consists of several stages. This README will explain the main vulnerability and the
stages of the sandbox escape step-by-step.


Impersonating system services
---------------------------------------------------------------------------------------------------

While researching crash reporting on iOS, I discovered a Mach port replacement vulnerability in
launchd. By crashing in a particular way, a process can make the kernel send a Mach message to
launchd that causes launchd to over-deallocate a send right to a Mach port in its IPC namespace.
This allows an attacker to impersonate any launchd service it can look up to the rest of the
system, which opens up numerous avenues to privilege escalation.

This vulnerability is also present on macOS, but triggering the vulnerability on iOS is more
difficult due to checks in launchd that ensure that the Mach exception message comes from the
kernel.


### CVE-2018-4280: launchd Mach port over-deallocation while handling EXC_CRASH exception messages

Launchd multiplexes multiple different Mach message handlers over its main port, including a MIG
handler for exception messages. If a process sends a `mach_exception_raise` or
`mach_exception_raise_state_identity` message to its own bootstrap port, launchd will receive and
process that message as a host-level exception.

Unfortunately, launchd's handling of these messages is buggy. If the exception type is `EXC_CRASH`,
then launchd will deallocate the thread and task ports sent in the message and then return
`KERN_FAILURE` from the service routine, causing the MIG system to deallocate the thread and task
ports again. (The assumption is that if a service routine returns success, then it has taken
ownership of all resources in the Mach message, while if the service routine returns an error, then
it has taken ownership of none of the resources.)

Here is the code from launchd's service routine for `mach_exception_raise` messages, decompiled
using IDA/Hex-Rays and lightly edited for readability:

```C
kern_return_t __fastcall
catch_mach_exception_raise(                             // (a) The service routine is
        mach_port_t            exception_port,          //     called with values directly
        mach_port_t            thread,                  //     from the Mach message
        mach_port_t            task,                    //     sent by the client. The
        exception_type_t       exception,               //     thread and task ports could
        mach_exception_data_t  code,                    //     be arbitrary send rights.
        mach_msg_type_number_t codeCnt)
{
    __int64 __stack_guard;                 // ST28_8@1
    kern_return_t kr;                      // w0@1 MAPDST
    kern_return_t result;                  // w0@4
    __int64 codes_left;                    // x25@6
    mach_exception_data_type_t code_value; // t1@7
    int pid;                               // [xsp+34h] [xbp-44Ch]@1
    char codes_str[1024];                  // [xsp+38h] [xbp-448h]@7

    __stack_guard = *__stack_chk_guard_ptr;
    pid = -1;
    kr = pid_for_task(task, &pid);
    if ( kr )
    {
        _os_assumes_log(kr);
        _os_avoid_tail_call();
    }
    if ( current_audit_token.val[5] )                   // (b) If the message was sent by
    {                                                   //     a process with a nonzero PID
        result = KERN_FAILURE;                          //     (any non-kernel process),
    }                                                   //     the message is rejected.
    else
    {
        if ( codeCnt )
        {
            codes_left = codeCnt;
            do
            {
                code_value = *code;
                ++code;
                __snprintf_chk(codes_str, 0x400uLL, 0, 0x400uLL, "0x%llx", code_value);
                --codes_left;
            }
            while ( codes_left );
        }
        launchd_log_2(
            0LL,
            3LL,
            "Host-level exception raised: pid = %d, thread = 0x%x, "
                "exception type = 0x%x, codes = { %s }",
            pid,
            thread,
            exception,
            codes_str);
        kr = deallocate_port(thread);                   // (c) The "thread" port sent in
        if ( kr )                                       //     the message is deallocated.
        {
            _os_assumes_log(kr);
            _os_avoid_tail_call();
        }
        kr = deallocate_port(task);                     // (d) The "task" port sent in the
        if ( kr )                                       //     message is deallocated.
        {
            _os_assumes_log(kr);
            _os_avoid_tail_call();
        }
        if ( exception == EXC_CRASH )                   // (e) If the exception type is
            result = KERN_FAILURE;                      //     EXC_CRASH, then KERN_FAILURE
        else                                            //     is returned. MIG will
            result = 0;                                 //     deallocate the ports again.
    }
    *__stack_chk_guard_ptr;
    return result;
}
```

This is what the code does:

1. This function is the Mach service routine for `mach_exception_raise` exception messages: it gets
   invoked directly by the Mach system when launchd processes a `mach_exception_raise` Mach
   exception message. The arguments to the service routine are parsed from the Mach message, and
   hence are controlled by the message's sender.
2. At (b), launchd checks that the Mach exception message was sent by the kernel. The sender's
   audit token contains the PID of the sending process in field 5, which will only be zero for the
   kernel. If the message wasn't sent by the kernel, it is rejected.
3. The thread and task ports from the message are explicitly deallocated at (c) and (d).
4. At (e), launchd checks whether the exception type is `EXC_CRASH`, and returns `KERN_FAILURE` if
   so. The intent is to make sure not to handle `EXC_CRASH` messages, presumably so that
   ReportCrash is invoked as the corpse handler. However, returning `KERN_FAILURE` at this point
   will cause the task and thread ports to be deallocated again when the exception message is
   cleaned up later. This means those two ports will be over-deallocated.

In order for this vulnerability to be useful, we will want to free launchd's send right to a Mach
service it vends, so that we can then impersonate that service to the rest of the system. This
means that we'll need the task and thread ports in the exception message to really be send rights
to the Mach service port we want to free in launchd. Then, once we've sent launchd the malicious
exception message and freed the service port, we will try to get that same port name reused, but
this time for a Mach port to which we hold the receive right. That way, when a client asks launchd
to give them a send right to the Mach port for the service, launchd will instead give them a send
right to our port, letting us impersonate that service to the client. After that, there are many
different routes to gain system privileges.


### Triggering the vulnerability

In order to actually trigger the vulnerability, we'll need to bypass the check that the message was
sent by the kernel. This is because if we send the exception message to launchd directly it will
just be discarded. Somehow, we need to get the kernel to send a "malicious" exception message
containing a Mach send right for a system service instead of the real thread and task ports.

As it turns out, there is a Mach trap, `task_set_special_port`, that can be used to set a custom
send right to be used in place of the true task port in certain situations. One of these situations
is when the kernel generates an exception message on behalf of a task: instead of placing the true
task send right in the exception message, the kernel will use the send right supplied by
`task_set_special_port`. More specifically, if a task calls `task_set_special_port` to set a custom
value for its `TASK_KERNEL_PORT` special port and then the task crashes, the exception message
generated by the kernel will have a send right to the custom port, not the true task port, in the
"task" field. An equivalent API, `thread_set_special_port`, can be used to set a custom port in the
"thread" field of the generated exception message.

Because of this behavior, it's actually not difficult at all to make the kernel generate a
"malicious" exception message containing a Mach service port in place of the task and thread port.
However, we still need to ensure that the exception message that we generate gets delivered to
launchd.

Once again, making sure the kernel delivers the "malicious" exception message to launchd isn't
difficult if you know the right API. The function `thread_set_exception_ports` will set any Mach
send right as the port to which exception messages on this thread are delivered. Thus, all we need
to do is invoke `thread_set_exception_ports` with the bootstrap port, and then any exception we
generate will cause the kernel to send an exception message to launchd.

The last piece of the puzzle is getting the right exception type. The vulnerability will only be
triggered for `EXC_CRASH` exceptions. A little trial and error reveals that we can easily generate
`EXC_CRASH` exceptions by calling the standard `abort` function.

Thus, in summary, we can use existing and well-documented APIs to make the kernel generate a
malicious `EXC_CRASH` exception message on our behalf and deliver it to launchd, triggering the
vulnerability and freeing the Mach service port:

1. Use `thread_set_exception_ports` to set launchd as the exception handler for this thread.
2. Call `bootstrap_look_up` to get the service port for the service we want to impersonate from
   launchd.
3. Call `task_set_special_port`/`thread_set_special_port` to use that service port instead of the
   true task and thread ports in exception messages.
4. Call `abort`. The kernel will send an `EXC_CRASH` exception message to launchd, but the task and
   thread ports in the message will be the target service port.
5. Launchd will process the exception message and free the service port.


### Running code after the crash

There's a problem with the above strategy: calling `abort` will kill our process. If we want to be
able to run any code at all after triggering the vulnerability, we need a way to perform the crash
in another process.

(With other exception types a process could actually recover from the exception. The way a process
would recover is to set its thread exception handler to be launchd and its task exception handler
to be itself. After launchd processes and fails to handle the exception, the kernel would send the
exception to the task handler, which would reset the thread state and inform the kernel that the
exception has been handled. However, a process cannot catch its own `EXC_CRASH` exceptions, so we
do need two processes.)

One strategy is to first exploit a vulnerability in another process on iOS and force that process
to set its kernel ports and crash. However, for a proof-of-concept, it's easier to create an app
extension.

App extensions, introduced in iOS 8, provide a way to package some functionality of an application
so it is available outside of the application. The code of an app extension runs in a separate,
sandboxed process. This makes it very easy to launch a process that will set its special ports,
register launchd as its exception handler for `EXC_CRASH`, and then call `abort`.

There is no supported way for an app to programatically launch its own app extension and talk to
it. However, Ian McDowell wrote a [great article][Multi-Process iOS App Using NSExtension]
describing how to use the private `NSExtension` API to launch and communicate with an app extension
process. I've used an almost identical strategy here. The only difference is that we need to
communicate a Mach port to the app extension process, which involves registering a dummy service
with launchd to which the app extension connects.

[Multi-Process iOS App Using NSExtension]: https://ianmcdowell.net/blog/nsextension/


### Preventing port reuse in launchd

One challenge you would notice if you ran the exploit as described is that occasionally you would
not be able to reacquire the freed port. The reason for this is that the kernel tracks a process's
free IPC entries in a freelist, and so a just-freed port name will be reused (with a different
generation number) when a new port is allocated in the IPC table. Thus, we will only reallocate the
port name we want if launchd doesn't reuse that IPC entry slot for another port first.

The way around this is to bury the free IPC entry slot down the freelist, so that if launchd
allocates new ports those other slots will be used first. How do we do this? We can register a
bunch of dummy Mach services in launchd with ports to which we hold the receive right. When we call
`abort`, the exception handler will fire first, and then the process state, including the Mach
ports, will be cleaned up. When launchd receives the `EXC_CRASH` exception it will inadvertently
free the target service port, placing the IPC entry slot corresponding to that port name at the
head of the freelist. Then, when the rest of our app extension's Mach ports are destroyed, launchd
will receive notifications and free the dummy service ports, burying the target IPC entry slot
behind the slots for the just-freed ports. Thus, as long as launchd allocates fewer ports than the
number of dummy services we registered, the target slot will still be on the freelist, meaning we
can still cause launchd to reallocate the slot with the same port name as the original service.

The limitation of this strategy is that we need the `com.apple.security.application-groups`
entitlement in order to register services with launchd. There are other ways to stash Mach ports in
launchd, but using application groups is certainly the easiest, and suffices for this
proof-of-concept.


### Impersonating the freed service

Once we have spawned the crasher app extension and freed a Mach send right in launchd, we need to
reallocate that Mach port name with a send right to which we hold the receive right. That way, any
messages launchd sends to that port name will be received by us, and any time launchd shares that
port name with a client, the client will receive a send right to our port. In particular, if we can
free launchd's send right to a Mach service, then any process that requests that service from
launchd will receive a send right to our own port instead of the real service port. This allows us
to impersonate the service or perform a man-in-the-middle attack, inspecting all messages that the
client sends to the service.

Getting the freed port name reused so that it refers to a port we own is also quite simple, given
that we've already decided to use the application-groups entitlement: just register dummy Mach
services with launchd until one of them reuses the original port name. We'll need to do it in
batches, registering a large number of dummy services together, checking to see if any has
successfully reused the freed port name, and then deregistering them. The reason is that we need to
be sure that our registrations go all the way back in the IPC port freelist to recover the buried
port name we want.

We can check whether we've managed to successfully reuse the freed port name by looking up the
original service with `bootstrap_look_up`: if it returns one of our registered service ports, we're
done.

Once we've managed to register a new service that gets the same port name as the original, any
clients that look up the original service in launchd will be given a send right to our port, not
the real service port. Thus, we are effectively impersonating the original service to the rest of
the system (or at least, to those processes that look up the service after our attack).


Stage 1: Obtaining the host-priv port
---------------------------------------------------------------------------------------------------

Once we have the capability to impersonate arbitrary system services, the next step is to obtain
the host-priv port. This step is straightforward, and is not affected by the changes in iOS 11.3.
The high-level idea of this attack is to impersonate SafetyNet, crash ReportCrash, and then
retrieve the host-priv port from the dying ReportCrash task port sent in the exception message.


### About ReportCrash and SafetyNet

ReportCrash is responsible for generating crash reports on iOS. This one binary actually vends 4
different services (each in a different process, although not all may be running at any given
time):

1. `com.apple.ReportCrash` is responsible for generating crash reports for crashing processes. It
   is the host-level exception handler for `EXC_CRASH`, `EXC_GUARD`, and `EXC_RESOURCE` exceptions.
2. `com.apple.ReportCrash.Jetsam` handles Jetsam reports.
3. `com.apple.ReportCrash.SimulateCrash` creates reports for simulated crashes.
4. `com.apple.ReportCrash.SafetyNet` is the registered exception handler for the
   `com.apple.ReportCrash` service.

The ones of interest to us are `com.apple.ReportCrash` and `com.apple.ReportCrash.SafetyNet`,
hereafter referred to simply as ReportCrash and SafetyNet. Both of these are MIG-based services,
and they run effectively the same code.

When ReportCrash starts up, it looks up the SafetyNet service in launchd and sets the returned port
as the task-level exception handler. The intent seems to be that if ReportCrash itself were to
crash, a separate process would generate the crash report for it. However, this code path looks
defunct: ReportCrash registers SafetyNet for `mach_exception_raise` messages, even though both
ReportCrash and SafetyNet only handle `mach_exception_raise_state_identity` messages. Nonetheless,
both services are still present and reachable from within the iOS container sandbox.


### ReportCrash manipulation primitives

In order to carry out the following attack, we need to be able to manipulate ReportCrash (or
SafetyNet) to behave in the way we want. Specifically, we need the following capabilities: start
ReportCrash on demand, force ReportCrash to exit, crash ReportCrash, and make sure that ReportCrash
doesn't exit while we're using it. Here I'll describe how we achieve each objective.

In order to start ReportCrash, we simply need to send it a Mach message: launchd will start it on
demand. However, due to its peculiar design, any message type except
`mach_exception_raise_state_identity` will cause ReportCrash to stop responding to new messages and
eventually exit. Thus, we need to send a `mach_exception_raise_state_identity` message if we want
it to stay alive afterwards.

In order to exit ReportCrash, we can simply send it any other type of Mach message.

There are many ways to crash ReportCrash. The easiest is probably to send a
`mach_exception_raise_state_identity` message with the thread port set to `MACH_PORT_NULL`.

Finally, we need to ensure that ReportCrash does not exit while we're using it. Each
`mach_exception_raise_state_identity` message that it processes causes it to spin off another
thread to listen for the next message while the original thread generates the crash report.
ReportCrash will exit once all of the outstanding threads generating a crash report have finished.
Thus, if we can stall one of those threads while it is in the process of generating a crash report,
we can keep it from ever exiting.

The easiest way I found to do that was to send a `mach_exception_raise_state_identity` message with
a custom port in the task and thread fields. Once ReportCrash tries to generate a crash report, it
will call `task_policy_get` on the "task" port, which will cause it to send a Mach message to the
port that we sent and await a reply. But since the "task" port is just a regular old Mach port, we
can simply not reply to the Mach message, and ReportCrash will wait indefinitely for
`task_policy_get` to return.


### Extracting host-priv from ReportCrash

For the first stage of the exploit, the attack plan is relatively straightforward:

1. Start the SafetyNet service and force it to stay alive for the duration of our attack.
2. Use the launchd service impersonation primitive to impersonate SafetyNet. This gives us a new
   port on which we can receive messages intended for the real SafetyNet service.
3. Make any existing instance of ReportCrash exit. That way, we can ensure that ReportCrash looks
   up our SafetyNet port in the next step.
4. Start ReportCrash. ReportCrash will look up SafetyNet in launchd and set the resulting port,
   which is the fake SafetyNet port for which we own the receive right, as the destination for
   `EXC_CRASH` messages.
5. Trigger a crash in ReportCrash. After seeing that there are no registered handlers for the
   original exception type, ReportCrash will enter the process death phase. At this point XNU will
   see that ReportCrash registered the fake SafetyNet port to receive `EXC_CRASH` exceptions, so it
   will generate an exception message and send it to that port.
6. We then listen on the fake SafetyNet port for the `EXC_CRASH` message. It will be of type
   `mach_exception_raise`, which means it will contain ReportCrash's task port.
7. Finally, we use `task_get_special_port` on the ReportCrash task port to get ReportCrash's host
   port. Since ReportCrash is unsandboxed and runs as root, this is the host-priv port.

At the end of this stage of the sandbox escape, we end up with a usable host-priv port. This alone
demonstrates that this is a serious security issue.


Stage 2: Escaping the sandbox
---------------------------------------------------------------------------------------------------

Even though we have the host-priv port, our goal is to fully escape the sandbox and run code as
root with the `task_for_pid-allow` entitlement. The first step in achieving that is to simply escape
the sandbox.

Technically speaking there's no reason we need to obtain the host-priv port before escaping the
sandbox: these two steps are independent and can occur in either order. However, this stage will
leave the system unstable if it or subsequent stages fail, so it's worth putting later.

The high-level attack is to use the same launchd vulnerability again to impersonate a system
service. However, this time our goal is to impersonate a service to which a client will send its
task port in a Mach message. It's easy to find by experimentation on iOS 11.2.6 that if we
impersonate `com.apple.CARenderServer` (hereafter CARenderServer) hosted by backboardd and then
communicate with `com.apple.DragUI.druid.source`, the unsandboxed druid daemon will send its task
port in a Mach message to the fake service port.

This step of the exploit is broken on iOS 11.3 because druid no longer sends its task port in the
Mach message to CARenderServer. Despite this, I'm confident that this vulnerability can still be
used to escape the sandbox. One way to go about this is to look for unsandboxed services that trust
input from other services. These types of "vulnerabilities" would never be exploitable without the
capability to replace system services, which means they are probably a low-priority attack surface,
both internally and externally to Apple.


### Crashing druid

Just like with ReportCrash, we need to be able to force druid to restart in case it is already
running so that it looks up our fake CARenderServer port in launchd. I decided to use a bug in
libxpc that was already scheduled to be fixed for this purpose.

While looking through libxpc, I found an out-of-bounds read that could be used to force any XPC
service to crash:

```C
void _xpc_dictionary_apply_wire_f
(
        OS_xpc_dictionary *xdict,
        OS_xpc_serializer *xserializer,
        const void *context,
        bool (*applier_fn)(const char *, OS_xpc_serializer *, const void *)
)
{
...
    uint64_t count = (unsigned int)*serialized_dict_count;
    if ( count )
    {
        uint64_t depth = xserializer->depth;
        uint64_t index = 0;
        do
        {
            const char *key = _xpc_serializer_read(xserializer, 0, 0, 0);
            size_t keylen = strlen(key);
            _xpc_serializer_advance(xserializer, keylen + 1);
            if ( !applier_fn(key, xserializer, context) )
                break;
            xserializer->depth = depth;
            ++index;
        }
        while ( index < count );
    }
...
}
```

The problem is that the use of an unchecked `strlen` on attacker-controlled data allows the key for
the serialized dictionary entry to extend beyond the end of the data buffer. This means the XPC
service deserializing the dictionary will crash, either when `strlen` dereferences out-of-bounds
memory or when `_xpc_serializer_advance` tries to advance the serializer past the end of the
supplied data.

This bug was already fixed in iOS 11.3 Beta by the time I discovered it, so I did not report it to
Apple. The exploit is available as an independent project in my [xpc-crash] repository.

[xpc-crash]: https://github.com/bazad/xpc-crash

In order to use this bug to crash druid, we simply need to send the druid service a malformed XPC
message such that the dictionary's key is unterminated and extends to the last byte of the message.


### Obtaining druid's task port

Obtaining druid's task port on iOS 11.2.6 using our service impersonation primitive is easy:

1. Use the Mach service impersonation capability to impersonate CARenderServer.
2. Send a message to the druid service so that it starts up.
3. If we don't get druid's task port after a few seconds, kill druid using the XPC bug and restart
   it.
4. Druid will send us its task port on the fake CARenderServer port.


### Getting around the platform binary task port restrictions

Once we have druid's task port, we still need to figure out how to execute code inside the druid
process.

The problem is that XNU protects task ports for platform binaries from being modified by
non-platform binaries. The defense is implemented in the function `task_conversion_eval`, which is
called by `convert_port_to_locked_task` and `convert_port_to_task_with_exec_token`:

```C
kern_return_t
task_conversion_eval(task_t caller, task_t victim)
{
	/*
	 * Tasks are allowed to resolve their own task ports, and the kernel is
	 * allowed to resolve anyone's task port.
	 */
	if (caller == kernel_task) {
		return KERN_SUCCESS;
	}

	if (caller == victim) {
		return KERN_SUCCESS;
	}

	/*
	 * Only the kernel can can resolve the kernel's task port. We've established
	 * by this point that the caller is not kernel_task.
	 */
	if (victim == kernel_task) {
		return KERN_INVALID_SECURITY;
	}

#if CONFIG_EMBEDDED
	/*
	 * On embedded platforms, only a platform binary can resolve the task port
	 * of another platform binary.
	 */
	if ((victim->t_flags & TF_PLATFORM) && !(caller->t_flags & TF_PLATFORM)) {
#if SECURE_KERNEL
		return KERN_INVALID_SECURITY;
#else
		if (cs_relax_platform_task_ports) {
			return KERN_SUCCESS;
		} else {
			return KERN_INVALID_SECURITY;
		}
#endif /* SECURE_KERNEL */
	}
#endif /* CONFIG_EMBEDDED */

	return KERN_SUCCESS;
}
```

MIG conversion routines that rely on these functions, including `convert_port_to_task` and
`convert_port_to_map`, will thus fail when we call them on druid's task. For example,
`mach_vm_write` won't allow us to manipulate druid's memory.

However, while looking at the MIG file `osfmk/mach/task.defs` in XNU, I noticed something
interesting:

```C
/*
 *	Returns the set of threads belonging to the target task.
 */
routine task_threads(
		target_task	: task_inspect_t;
	out	act_list	: thread_act_array_t);
```

The function `task_threads`, which enumerates the threads in a task, actually takes a
`task_inspect_t` rather than a `task_t`, which means MIG converts it using
`convert_port_to_task_inspect` rather than `convert_port_to_task`. A quick look at
`convert_port_to_task_inspect` reveals that this function does not perform the
`task_conversion_eval` check, meaning we can call it successfully on platform binaries. This is
interesting because the returned threads are not `thread_inspect_t` rights, but rather full
`thread_act_t` rights. Put another way, `task_threads` promotes a non-modifiable task right into
modifiable thread rights. And since there's no equivalent `thread_conversion_eval`, this means we
can use the Mach thread APIs to modify the threads in a task even if that task is a platform
binary.

In order to take advantage of this, I wrote a library called [threadexec] which builds a
full-featured function call capability on top of the Mach threads API. The threadexec project in
and of itself was a significant undertaking, but as it is only indirectly relevant to this exploit,
I will forego a detailed explanation of its inner workings.

[threadexec]: https://github.com/bazad/threadexec


Stage 3: Installing a new host-level exception handler
---------------------------------------------------------------------------------------------------

Once we have the host-priv port and unsandboxed code execution inside of druid, the next stage of
the full sandbox escape is to install a new host-level exception handler. This process is
straightforward given our current capabilities:

1. Get the current host-level exception handler for `EXC_BAD_ACCESS` by calling
   `host_get_exception_ports`.
2. Allocate a Mach port that will be the new host-level exception handler for `EXC_BAD_ACCESS`.
3. Send the host-priv port and a send right to the Mach port we just allocated over to druid.
4. Using our execution context in druid, make druid call `host_set_exception_ports` to register our
   Mach port as the host-level exception handler for `EXC_BAD_ACCESS`.

After this stage, any time a process accesses an invalid memory address (and also does not have a
registered exception handler), an `EXC_BAD_ACCESS` exception message will be sent to our new
exception handler port. This will give us the task port of any crashing process, and since
`EXC_BAD_ACCESS` is a recoverable exception, this time we can use the task port to execute code.


Stage 4: Getting ReportCrash's task port
---------------------------------------------------------------------------------------------------

The next stage is to trigger an `EXC_BAD_ACCESS` exception in ReportCrash so that its task port
gets sent in an exception message to our new exception handler port:

1. Crash ReportCrash using the previously described technique. This will cause ReportCrash to
   generate an `EXC_BAD_ACCESS` exception. Since ReportCrash has no exception handler registered
   for `EXC_BAD_ACCESS` (remember SafetyNet is registered for `EXC_CRASH`), the exception will be
   delivered to the host-level exception handler.
2. Listen for exception messages on our host exception handler port.
3. When we receive the exception message for ReportCrash, save the task and thread ports. Suspend
   the crashing thread and return `KERN_SUCCESS` to indicate to the kernel that the exception has
   been handled and ReportCrash can be resumed.
4. Use the task and thread ports to establish an execution context inside ReportCrash just like we
   did with druid.

At this point, we have code execution inside an unsandboxed, root, `task_for_pid-allow` process.


Stage 5: Restoring the original host-level exception handler
---------------------------------------------------------------------------------------------------

The next two stages aren't strictly necessary but should be performed anyway.

Once we have code execution inside ReportCrash, we should reset the host-level exception handler
for `EXC_BAD_ACCESS` using druid:

1. Send the old host-level exception handler port over to druid.
2. Call `host_set_exception_ports` in druid to re-register the old host-level exception handler for
   `EXC_BAD_ACCESS`.

This will stop our exception handler port from receiving exception messages for other crashing
processes.


Stage 6: Fixing up launchd
---------------------------------------------------------------------------------------------------

The last step is to restore the damage we did to launchd when we freed service ports in its IPC
namespace in order to impersonate them:

1. Call `task_for_pid` in ReportCrash to get launchd's task port.
2. For each service we impersonated:
    1. Get launchd's name for the send right to the fake service port. This is the original name of
       the real service port.
    2. Destroy the fake service port, deregistering the fake service with launchd.
    3. Call `mach_port_insert_right` in ReportCrash to push the real service port into launchd's
       IPC space under the original name.

After this step is done, the system should once again be fully functional. After successful
exploitation, there should be no need to force reset the device, since the exploit repairs all the
damages itself.


Post-exploitation
---------------------------------------------------------------------------------------------------

Blanket also packages a post-exploitation payload that bypasses amfid and spawns a bind shell. This
section will describe how that is achieved.


### Spawning a payload process

Even after gaining code execution in ReportCrash, using that capability is not easy: we are limited
to performing individual function calls from within the process, which makes it painful to perform
complex tasks. Ideally, we'd like a way to run code natively with ReportCrash's privileges, either
by injecting code into ReportCrash or by spawning a new process with the same (or higher)
privileges.

Blanket chooses the process spawning route. We use `task_for_pid` and our platform binary status in
ReportCrash to get launchd's task port and create a new thread inside of launchd that we can
control. We then use that thread to call `posix_spawn` to launch our payload binary. The payload
binary can be signed with restricted entitlements, including `task_for_pid-allow`, to grant
additional capabilities.


### Bypassing amfid

In order for iOS to accept our newly spawned binary, we need to bypass codesigning. Various
strategies have been discussed over the years, but the most common current strategy is to register
an exception handler for amfid and then perform a data patch so that amfid crashes when trying to
call `MISValidateSignatureAndCopyInfo`. This allows us to fake the implementation of that function
to pretend that the code signature is valid.

However, there's another approach which I believe is more robust and flexible: rather than patching
amfid at all, we can simply register a new amfid port in the kernel.

The kernel keeps track of which port to send messages to amfid using a host special port called
`HOST_AMFID_PORT`. If we have unsandboxed root code execution, we can set this port to a new value.
Apple has protected against this attack by checking whether the reply to a validation request
really came from amfid: the cdhash of the sender is compared to amfid's cdhash. However, this
doesn't actually prevent the message from being sent to a process other than amfid; it only
prevents the reply from coming from a non-amfid process. If we set up a triangle where the kernel
sends messages to us, we generate the reply and pass it to amfid, and then amfid sends the reply to
the kernel, then we'll be able to bypass the sender check.

There are numerous advantages to this approach, of which the biggest is probably access to
additional flags in the `verify_code_directory` service routine. Even though amfid does not use
them all, there are many other output flags that amfid could set to control the behavior of
codesigning. Here's a partial prototype of `verify_code_directory`:

```C
kern_return_t
verify_code_directory(
		mach_port_t    amfid_port,
		amfid_path_t   path,
		uint64_t       file_offset,
		int32_t        a4,
		int32_t        a5,
		int32_t        a6,
		int32_t *      entitlements_valid,
		int32_t *      signature_valid,
		int32_t *      unrestrict,
		int32_t *      signer_type,
		int32_t *      is_apple,
		int32_t *      is_developer_code,
		amfid_a13_t    a13,
		amfid_cdhash_t cdhash,
		audit_token_t  audit);
```

Of particular interest for jailbreak developers is the `is_apple` parameter. This parameter does
not appear to be used by amfid, but if set, it will cause the kernel to set the
`CS_PLATFORM_BINARY` codesigning flag, which grants the application platform binary privileges. In
particular, this means that the application can now use task ports to modify platform binaries
directly.


Loopholes used in this attack
---------------------------------------------------------------------------------------------------

This attack takes advantage of several loopholes that aren't security vulnerabilities themselves
but do minimize the effectiveness of various exploit mitigations. Not all of these need to be
closed together, since some are partially redundant, but it's worth listing them all anyway.

In the kernel:

1. `task_threads` can promote an inspect-only `task_inspect_t` to a modify-capable `thread_act_t`.
2. There is no `thread_conversion_eval` to perform the role of `task_conversion_eval` for threads.
3. A non-platform binary may use a `task_inspect_t` right for a platform binary.
4. Exception messages for unsandboxed processes may be delivered to sandboxed processes, even
   though that provides a way to escape the sandbox. It's not clear whether there is a clean fix
   for this loophole.
5. Unsandboxed code execution, the host-priv port, and the ability to crash a `task_for_pid-allow`
   process can be combined to build a `task_for_pid` workaround. (The workaround is: call
   `host_set_exception_ports` to set a new host-level exception handler, then crash the
   `task_for_pid-allow` process to receive its task port and execute code with the entitlement.)

In app extensions:

1. App extensions that share an application group can communicate using Mach messages, despite the
   documentation suggesting that communication between the host app and the app extension should be
   impossible.


Recommended fixes and mitigations
---------------------------------------------------------------------------------------------------

I recommend the following fixes, roughly in order of importance:

1. Only deallocate Mach ports in the launchd service routines when returning `KERN_SUCCESS`. This
   will fix the Mach port replacement vulnerability.
2. Close the `task_threads` loophole allowing a non-platform binary to use the task port of a
   platform binary to achieve code execution.
3. Fix crashing issues in ReportCrash.
4. The set of Mach services reachable from within the container sandbox should be minimized. I do
   not see a legitimate reason for most iOS apps to communicate with ReportCrash or SafetyNet.
5. As many processes as possible should be sandboxed. I'm not sure whether druid needs to be
   unsandboxed to function properly, but if not, it should be placed in an appropriate sandbox.
6. Dead code should be eliminated. SafetyNet does not seem to be performing its intended
   functionality. If it is no longer needed, it should probably be removed.
7. Close the `host_set_exception_ports`-based `task_for_pid` workaround. For example, consider
   whether it's worth restricting `host_set_exception_ports` to root or restricting the usability
   of the host-priv port under some configurations. This violates the elegant capabilities-based
   design of Mach, but `host_set_exception_ports` might be a promising target for abuse.
8. Consider whether it's worth adding `task_conversion_eval` to `task_inspect_t`.


Running blanket
---------------------------------------------------------------------------------------------------

Blanket should work on any device running iOS 11.2.6.

1. Download the project:
   ```
   git clone https://github.com/bazad/blanket
   cd blanket
   ```
2. Download and build the threadexec library, which is required for blanket to inject code in
   processes and tasks:
   ```
   git clone https://github.com/bazad/threadexec
   cd threadexec
   make ARCH=arm64 SDK=iphoneos
   cd ..
   ```
3. Download Jonathan Levin's [iOS binpack], which contains the binaries that will be used by the
   bind shell. If you change the payload to do something else, you won't need the binpack.
   ```
   mkdir binpack
   curl http://newosxbook.com/tools/binpack64-256.tar.gz | tar -xf- -C binpack
   ```
4. Open Xcode and configure the project. You will need to change the signing identifier and specify
   a custom application group entitlement.
5. Edit the file `headers/config.h` and change `APP_GROUP` to whatever application group identifier
   you specified earlier.

[iOS binpack]: http://newosxbook.com/tools/iOSBinaries.html

After that, you should be able to build and run the project on the device.

If blanket is successful, it will run the payload binary (source in
`blanket_payload/blanket_payload.c`), which by default spawns a bind shell on port 4242. You can
connect to that port with netcat and run arbitrary shell commands.


Credits
---------------------------------------------------------------------------------------------------

Many thanks to Ian Beer and Jonathan Levin for their excellent iOS security and internals research.


Timeline
---------------------------------------------------------------------------------------------------

I discovered this vulnerability in January of 2018, and started developing the exploit in late
February. I reported this issue to Apple on April 13. Apple assigned the Mach port replacement
vulnerability in launchd CVE-2018-4280, and it was patched in [iOS 11.4.1] and [macOS 10.13.6] on
July 9.

[iOS 11.4.1]: https://support.apple.com/en-us/HT208938
[macOS 10.13.6]: https://support.apple.com/en-us/HT208937


License
---------------------------------------------------------------------------------------------------

Blanket is released under the MIT license.


---------------------------------------------------------------------------------------------------
Brandon Azad
