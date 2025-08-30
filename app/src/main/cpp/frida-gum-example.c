/*
 * Compile with:
 *
 * clang -DANDROID -ffunction-sections -fdata-sections frida-gum-example.c -o frida-gum-example -L. -lfrida-gum -llog -ldl -lm -pthread
 *
 * Visit https://frida.re to learn more about Frida.
 */

#include "frida-gum.h"
#include "Logger.h"

#include <fcntl.h>
#include <unistd.h>

typedef struct _ExampleListenerData ExampleListenerData;
typedef enum _ExampleHookId ExampleHookId;

struct _ExampleListenerData
{
  guint num_calls;
};

enum _ExampleHookId
{
  EXAMPLE_HOOK_OPEN,
  EXAMPLE_HOOK_CLOSE
};

static void example_listener_on_enter (GumInvocationContext * ic, gpointer user_data);
static void example_listener_on_leave (GumInvocationContext * ic, gpointer user_data);

int
test_gum_example ()
{
    LOGD("test hook begin");
  GumInterceptor * interceptor;
  ExampleListenerData * data;
  GumInvocationListener * listener;

  gum_init_embedded ();   // 初始化

  interceptor = gum_interceptor_obtain ();

  data = g_new0 (ExampleListenerData, 1);
  listener = gum_make_call_listener (example_listener_on_enter, example_listener_on_leave, data, g_free);

  gum_interceptor_begin_transaction (interceptor);
  gum_interceptor_attach (interceptor,
      GSIZE_TO_POINTER (gum_module_find_global_export_by_name ("open")),
      listener,
      GSIZE_TO_POINTER (EXAMPLE_HOOK_OPEN),
      GUM_ATTACH_FLAGS_NONE);
  gum_interceptor_attach (interceptor,
      GSIZE_TO_POINTER (gum_module_find_global_export_by_name ("close")),
      listener,
      GSIZE_TO_POINTER (EXAMPLE_HOOK_CLOSE),
      GUM_ATTACH_FLAGS_NONE);
  gum_interceptor_end_transaction (interceptor);

  close (open ("/etc/hosts", O_RDONLY));
  close (open ("/etc/fstab", O_RDONLY));

  LOGD ("[*] listener got %u calls\n", data->num_calls);

  gum_interceptor_detach (interceptor, listener);

  close (open ("/etc/hosts", O_RDONLY));
  close (open ("/etc/fstab", O_RDONLY));

    LOGD ("[*] listener still has %u calls\n", data->num_calls);

  g_object_unref (listener);
  g_object_unref (interceptor);

  gum_deinit_embedded ();

  return 0;
}

static void
example_listener_on_enter (GumInvocationContext * ic,
                           gpointer user_data)
{
  ExampleListenerData * data = user_data;
  ExampleHookId hook_id;

  hook_id = GUM_IC_GET_FUNC_DATA (ic, ExampleHookId);

  switch (hook_id)
  {
    case EXAMPLE_HOOK_OPEN:
        LOGD ("[*] open(\"%s\")\n", (const gchar *) gum_invocation_context_get_nth_argument (ic, 0));
      break;
    case EXAMPLE_HOOK_CLOSE:
        LOGD ("[*] close(%d)\n", GPOINTER_TO_INT (gum_invocation_context_get_nth_argument (ic, 0)));
      break;
  }

  data->num_calls++;
}

static void
example_listener_on_leave (GumInvocationContext * ic,
                           gpointer user_data)
{
}
