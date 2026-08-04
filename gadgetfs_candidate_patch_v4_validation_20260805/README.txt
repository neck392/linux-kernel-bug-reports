GadgetFS candidate-patch validation artifacts
================================================

Baseline
--------

Linux v7.2-rc1
Commit: dc59e4fea9d83f03bad6bddf3fa2e52491777482
Runtime: x86_64 QEMU/KVM with dummy_hcd and gadgetfs

patches/candidate_v4.patch is the patch tested in this directory. Its
SHA-256 is recorded in SHA256SUMS.txt. It differs from the preceding
candidate revision by adding an iocb->private != NULL test before the
post-queue priv->req_state access.

The diagnostic patches are not proposed fixes. One widens the post-queue
state-check window used to retest the previous revision's ep_aio() UAF:

  diagnostic_postqueue_50ms.patch

The other two widen the interval after usb_ep_dequeue() returns and before
ep_aio_cancel() performs its usb_ep_free_request() and put_ep() cleanup:

  diagnostic_post_dequeue_50ms.patch
  diagnostic_post_dequeue_15s.patch

The 50-ms diagnostic build used the built-in config. The 15-second build
used the modular config. The two configs differ only in:

  CONFIG_USB_GADGETFS=y
  CONFIG_USB_GADGETFS=m

Both use KASAN_INLINE and PROVE_LOCKING.

Reproducer builds
-----------------

  gcc -O2 -Wall -Wextra -pthread \
    -o repro_previous_postqueue_uaf \
    reproducers/repro_previous_postqueue_uaf.c

  gcc -O2 -Wall -Wextra -pthread \
    -o repro_unbind_cancel_lifetime \
    reproducers/repro_unbind_cancel_lifetime.c

  gcc -O2 -Wall -Wextra -pthread \
    -o repro_module_unload_lifetime \
    reproducers/repro_module_unload_lifetime.c

  gcc -O2 -Wall -Wextra -pthread \
    -o repro_lockdep_sync_giveback \
    reproducers/repro_lockdep_sync_giveback.c

The focused invocations used for the included reports were:

  ./repro_previous_postqueue_uaf
  ./repro_unbind_cancel_lifetime 0 2000000 0 1
  ./repro_module_unload_lifetime 0 2000000 0 1
  ./repro_lockdep_sync_giveback 1000000 0 0 1 0 0

The reproducers use root for GadgetFS and dummy_hcd setup and then perform
the endpoint operations as uid/gid 1000.

Reports
-------

reports/previous_postqueue_uaf_v4_result.txt
  Result of repeated no-argument runs of the previous revision's
  post-queue UAF reproducer on the candidate-v4 kernel. No kernel signal
  was detected in those runs. This is scoped test evidence, not a proof
  that every possible interleaving is absent.

reports/unbind_cancel_lifetime_trace.txt
  Pointer-correlated trace from the 50-ms diagnostic build. For the target
  request, usb_ep_dequeue() returned at 37.788091. gadgetfs_unbind(),
  usb_gadget_unregister_driver(), and dev_release() returned by 37.799841.
  The cancel-side usb_ep_free_request(), put_ep(), and ep_aio_cancel()
  return occurred at 37.838240 through 37.838343.

reports/module_unload_lifetime_trace.txt
  Focused output from the valid modular diagnostic run. gadgetfs_unbind()
  returned while ep_aio_cancel() was paused. The process had no numeric
  GadgetFS file descriptors, the gadgetfs module reference count was 2,
  and rmmod failed with "Module gadgetfs is in use". dev_release() and the
  unmount completed after ep_aio_cancel() returned; removal then succeeded.

reports/lockdep_report_candidate_v4.txt
  Exact LOCKDEP warning section from the candidate-v4 kernel. Calling
  kiocb_set_cancel_fn() while ep_aio() holds dev->lock establishes the
  dev->lock to ctx->ctx_lock direction. Synchronous dequeue giveback from
  free_ioctx_users() supplies the reverse direction.

reports/lockdep_report_unpatched_control.txt
  Exact warning section from the matched unpatched control using the same
  config, reproducer, workload, timing arguments, and fresh-boot setup. It
  reports recursive ctx_lock acquisition in the same synchronous-giveback
  call chain. Therefore the underlying synchronous-giveback recursion is
  not attributed to the candidate patch; the dev->lock to ctx->ctx_lock
  dependency is the additional candidate-patch-specific edge.

Scope limits
------------

These observations were made with dummy_hcd. No physical or other UDC was
tested. The diagnostic delays deliberately change timing and are used only
to establish reachability and ordering. No KASAN or Oops was observed in
the included unbind and modular-lifetime orderings under dummy_hcd.

The modular result shows that existing file and module references prevented
module removal during ep_aio_cancel() in the tested path. It does not by
itself establish the lifetime of UDC-owned struct usb_ep or usb_request
objects after unbind and UDC teardown.
