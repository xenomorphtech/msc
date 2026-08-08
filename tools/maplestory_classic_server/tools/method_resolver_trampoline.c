/* One-shot Win64 IL2CPP metadata walk for gdb_resolve_method.py. */

typedef unsigned long long u64;
typedef void *pointer;

#define MS_ABI __attribute__((ms_abi))

typedef pointer(MS_ABI *pointer_function_0)(void);
typedef pointer(MS_ABI *pointer_function_1)(pointer);
typedef pointer(MS_ABI *pointer_function_2)(pointer, pointer);
typedef u64(MS_ABI *integer_function_1)(pointer);

struct resolve_context {
    u64 stage;
    pointer_function_0 domain_get;
    pointer_function_2 domain_get_assemblies;
    pointer_function_1 assembly_get_image;
    pointer_function_1 image_get_name;
    integer_function_1 image_get_class_count;
    pointer_function_2 image_get_class;
    pointer_function_2 class_get_methods;
    pointer_function_1 class_get_name;
    pointer_function_1 method_get_name;
    const char *assembly_name;
    const char *assembly_dll_name;
    pointer target;
    pointer domain;
    pointer assemblies;
    u64 assembly_count;
    pointer assembly;
    pointer image;
    u64 class_count;
    u64 visited_methods;
    pointer nearest_before_class;
    pointer nearest_before_method_info;
    pointer nearest_before_method;
    pointer nearest_after_class;
    pointer nearest_after_method_info;
    pointer nearest_after_method;
    const char *nearest_before_class_name;
    const char *nearest_before_method_name;
    const char *nearest_after_class_name;
    const char *nearest_after_method_name;
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

__attribute__((used, noinline)) MS_ABI void resolve_method(
    struct resolve_context *context
) {
    u64 class_index;

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
    for (class_index = 0; class_index < context->assembly_count; class_index++) {
        pointer assembly = ((pointer *)context->assemblies)[class_index];
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
    context->class_count = context->image_get_class_count(context->image);
    if (context->class_count == 0 || context->class_count >= 1000000) {
        return;
    }
    for (class_index = 0; class_index < context->class_count; class_index++) {
        pointer klass = context->image_get_class(context->image, (pointer)class_index);
        pointer iterator = (pointer)0;
        pointer method_info;
        if (klass == (pointer)0) {
            continue;
        }
        while ((method_info = context->class_get_methods(klass, &iterator)) !=
               (pointer)0) {
            pointer method = *(pointer *)method_info;
            context->visited_methods++;
            if (method == (pointer)0) {
                continue;
            }
            if (method <= context->target &&
                (context->nearest_before_method == (pointer)0 ||
                 method > context->nearest_before_method)) {
                context->nearest_before_class = klass;
                context->nearest_before_method_info = method_info;
                context->nearest_before_method = method;
            }
            if (method > context->target &&
                (context->nearest_after_method == (pointer)0 ||
                 method < context->nearest_after_method)) {
                context->nearest_after_class = klass;
                context->nearest_after_method_info = method_info;
                context->nearest_after_method = method;
            }
        }
    }
    if (context->nearest_before_class != (pointer)0) {
        context->nearest_before_class_name =
            context->class_get_name(context->nearest_before_class);
        context->nearest_before_method_name =
            context->method_get_name(context->nearest_before_method_info);
    }
    if (context->nearest_after_class != (pointer)0) {
        context->nearest_after_class_name =
            context->class_get_name(context->nearest_after_class);
        context->nearest_after_method_name =
            context->method_get_name(context->nearest_after_method_info);
    }
    context->stage = 100;
}
