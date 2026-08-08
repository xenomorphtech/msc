/* One-shot Win64 IL2CPP named-method lookup for GDB. */

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

struct named_method_context {
    u64 stage;
    pointer_function_0 domain_get;
    pointer_function_2 domain_get_assemblies;
    pointer_function_1 assembly_get_image;
    pointer_function_1 image_get_name;
    class_from_name_function class_from_name;
    class_get_method_function class_get_method_from_name;
    const char *assembly_name;
    const char *assembly_dll_name;
    const char *namespace_name;
    const char *class_name;
    const char *method_name;
    u64 argument_count;
    pointer domain;
    pointer assemblies;
    u64 assembly_count;
    pointer assembly;
    pointer image;
    pointer klass;
    pointer method_info;
    pointer method;
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

__attribute__((used, noinline)) MS_ABI void resolve_named_method(
    struct named_method_context *context
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
            (!strings_equal(name, context->assembly_name) &&
             !strings_equal(name, context->assembly_dll_name))) {
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
        context->image, context->namespace_name, context->class_name
    );
    if (context->klass == (pointer)0) {
        return;
    }

    context->stage = 5;
    context->method_info = context->class_get_method_from_name(
        context->klass, context->method_name, (int)context->argument_count
    );
    if (context->method_info == (pointer)0) {
        return;
    }
    context->method = *(pointer *)context->method_info;
    if (context->method == (pointer)0) {
        return;
    }
    context->stage = 100;
}
