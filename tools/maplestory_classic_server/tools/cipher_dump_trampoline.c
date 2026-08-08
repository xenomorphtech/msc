/* One-shot Win64 IL2CPP metadata walk for gdb_dump_cipher_arrays.py.
 *
 * This is compiled as freestanding position-independent code and temporarily
 * placed in an executable GameAssembly code page while all other threads are
 * stopped.  It makes every runtime call before returning to GDB because Wine
 * does not preserve the debugger-hijacked guest context across multiple
 * continue/stop cycles.
 */

typedef unsigned long long u64;
typedef void *pointer;

#define MS_ABI __attribute__((ms_abi))

typedef pointer(MS_ABI *pointer_function_0)(void);
typedef pointer(MS_ABI *pointer_function_1)(pointer);
typedef pointer(MS_ABI *pointer_function_2)(pointer, pointer);
typedef pointer(MS_ABI *class_from_name_function)(
    pointer, const char *, const char *
);
typedef pointer(MS_ABI *class_get_method_function)(
    pointer, const char *, int
);
typedef void(MS_ABI *void_function_1)(pointer);
typedef void(MS_ABI *void_function_2)(pointer, pointer);

struct dump_context {
    u64 stage;
    pointer_function_0 domain_get;
    pointer_function_2 domain_get_assemblies;
    pointer_function_1 assembly_get_image;
    pointer_function_1 image_get_name;
    class_from_name_function class_from_name;
    void_function_1 runtime_class_init;
    pointer_function_2 class_get_field_from_name;
    void_function_2 field_static_get_value;
    const char *empty_namespace;
    const char *class_name;
    const char *framework_name;
    const char *framework_dll_name;
    const char *field_names[6];
    pointer domain;
    pointer assemblies;
    u64 assembly_count;
    pointer assembly;
    pointer image;
    pointer klass;
    pointer arrays[6];
    u64 lengths[6];
    class_get_method_function class_get_method_from_name;
    const char *transform_names[2];
    pointer transform_method_infos[2];
    pointer transform_method_pointers[2];
    const char *inno_class_name;
    const char *inno_method_names[6];
    u64 inno_method_argument_counts[6];
    pointer inno_class;
    pointer inno_method_infos[6];
    pointer inno_method_pointers[6];
};

static inline __attribute__((always_inline)) int strings_equal(
    const char *left, const char *right
) {
    while (*left != 0 && *left == *right) {
        left++;
        right++;
    }
    return *left == *right;
}

__attribute__((used, noinline)) MS_ABI void dump_cipher_arrays(
    struct dump_context *context
) {
    u64 index;

    context->stage = 1;
    context->domain = context->domain_get();
    if (context->domain == (pointer)0) {
        return;
    }

    context->stage = 2;
    context->assemblies = context->domain_get_assemblies(
        context->domain, &context->assembly_count
    );
    if (context->assemblies == (pointer)0 || context->assembly_count == 0 ||
        context->assembly_count >= 10000) {
        return;
    }

    context->stage = 3;
    for (index = 0; index < context->assembly_count; index++) {
        pointer assembly = ((pointer *)context->assemblies)[index];
        pointer image = context->assembly_get_image(assembly);
        const char *name;
        if (image == (pointer)0) {
            continue;
        }
        name = (const char *)context->image_get_name(image);
        if (name == (const char *)0 ||
            (!strings_equal(name, context->framework_name) &&
             !strings_equal(name, context->framework_dll_name))) {
            continue;
        }
        context->assembly = assembly;
        context->image = image;
        break;
    }
    if (context->image == (pointer)0) {
        return;
    }

    context->stage = 4;
    context->klass = context->class_from_name(
        context->image, context->empty_namespace, context->class_name
    );
    if (context->klass == (pointer)0) {
        return;
    }

    context->stage = 5;
    context->runtime_class_init(context->klass);

    for (index = 0; index < 6; index++) {
        pointer field;
        pointer array = (pointer)0;
        context->stage = 10 + index;
        field = context->class_get_field_from_name(
            context->klass, (pointer)context->field_names[index]
        );
        if (field == (pointer)0) {
            return;
        }
        context->field_static_get_value(field, &array);
        if (array == (pointer)0) {
            return;
        }
        context->arrays[index] = array;
        context->lengths[index] = *(u64 *)((char *)array + 0x18);
    }
    for (index = 0; index < 2; index++) {
        pointer method_info;
        context->stage = 20 + index;
        method_info = context->class_get_method_from_name(
            context->klass, context->transform_names[index], 2
        );
        if (method_info == (pointer)0) {
            return;
        }
        context->transform_method_infos[index] = method_info;
        context->transform_method_pointers[index] = *(pointer *)method_info;
        if (context->transform_method_pointers[index] == (pointer)0) {
            return;
        }
    }

    context->stage = 30;
    context->inno_class = context->class_from_name(
        context->image, context->empty_namespace, context->inno_class_name
    );
    if (context->inno_class == (pointer)0) {
        return;
    }
    for (index = 0; index < 6; index++) {
        pointer method_info;
        context->stage = 31 + index;
        method_info = context->class_get_method_from_name(
            context->inno_class,
            context->inno_method_names[index],
            (int)context->inno_method_argument_counts[index]
        );
        if (method_info == (pointer)0) {
            return;
        }
        context->inno_method_infos[index] = method_info;
        context->inno_method_pointers[index] = *(pointer *)method_info;
        if (context->inno_method_pointers[index] == (pointer)0) {
            return;
        }
    }
    context->stage = 100;
}
