#include "ruby/ruby.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <seccomp.h>

#include <stdbool.h>

struct seccomp_data{
    scmp_filter_ctx ctx;
    bool is_released;
};

static VALUE syscall_hash; // hash table : { :syscall => syscall_number }
static VALUE eSeccompError;

static void rb_seccomp_free(void *sd);
static size_t rb_seccomp_memsize(const void *sd);
const rb_data_type_t Seccomp_data_type={
    "Seccomp",
    {
        NULL,
        rb_seccomp_free,
        rb_seccomp_memsize,
    },
    NULL, NULL
};

static VALUE rb_seccomp_allocate(VALUE klass)
{
    VALUE obj;
    struct seccomp_data *sd;
    obj=TypedData_Make_Struct(klass, struct seccomp_data, &Seccomp_data_type, sd);
    return obj;
}

static void rb_seccomp_free(void *obj)
{
    struct seccomp_data *sd=(struct seccomp_data*)obj;
    if(!sd->is_released){
        seccomp_release(sd->ctx);
    }
    xfree(obj);
}

static size_t rb_seccomp_memsize(const void *sd)
{
    return sizeof(struct seccomp_data);
}

static VALUE rb_seccomp_initialize(VALUE self)
{
    struct seccomp_data *sd=(struct seccomp_data*)RTYPEDDATA_DATA(self);
    sd->ctx=seccomp_init(SCMP_ACT_ALLOW);
    if (sd->ctx == NULL){
        rb_raise(eSeccompError, "seccomp_init");
    }
    return self;
}

static VALUE rb_seccomp_deny(VALUE self, VALUE syscall)
{
    struct seccomp_data *sd=(struct seccomp_data*)RTYPEDDATA_DATA(self);
    switch(TYPE(syscall)){
        case T_SYMBOL: break;
        default:
            rb_raise(eSeccompError, "1st argument is not symbol");
    }
    VALUE syscall_num=rb_funcall(syscall_hash, rb_intern("fetch"), 2, syscall, Qnil);
    if(syscall_num==Qnil){
        rb_raise(eSeccompError, "2nd argument is not syscall");
    }
    if(seccomp_rule_add(sd->ctx, SCMP_ACT_ERRNO(EPERM), NUM2LONG(syscall_num), 0)<0){
        rb_raise(eSeccompError, "seccomp_rule_add failed");
    }
    return self;
}

static VALUE rb_seccomp_rule_add(VALUE self, VALUE syscall, VALUE args)
{
    struct seccomp_data *sd=(struct seccomp_data*)RTYPEDDATA_DATA(self);
    switch(TYPE(syscall)){
        case T_SYMBOL: break;
        default:
            rb_raise(eSeccompError, "1st argument is not symbol");
    }
    switch(TYPE(args)){
        case T_HASH: break;
        default:
            rb_raise(eSeccompError, "2nd argument is not hash table");
    }
    rb_raise(eSeccompError, "not implemented");
    return self;
}

static VALUE rb_seccomp_load(VALUE self)
{
    struct seccomp_data *sd=(struct seccomp_data*)RTYPEDDATA_DATA(self);
    if (seccomp_load(sd->ctx) < 0){
        rb_raise(eSeccompError, "seccomp_load");
    }
    return self;
}

static VALUE rb_seccomp_release(VALUE self)
{
    struct seccomp_data *sd=(struct seccomp_data*)RTYPEDDATA_DATA(self);
    if(!sd->is_released){
        seccomp_release(sd->ctx);
        sd->is_released=true;
    }
    return Qnil;
}

void Init_seccomp(void){
    VALUE cSeccomp=rb_define_class("Seccomp", rb_cObject);

    syscall_hash=rb_eval_string(
        "s=File.read('/usr/include/asm/unistd_64.h')\n"
        "arr=s.scan(/^#define __NR_(\\w+)\\s(\\d+)$/).map{ |k,v| [k.to_sym,v.to_i] }\n"
        "Hash[*arr.flatten]\n"
    );

    rb_define_method(cSeccomp, "initialize", rb_seccomp_initialize, 0);
    rb_define_method(cSeccomp, "rule_add", rb_seccomp_rule_add, 2);
    rb_define_method(cSeccomp, "load", rb_seccomp_load, 0);
    rb_define_method(cSeccomp, "release", rb_seccomp_release, 0);

    rb_define_method(cSeccomp, "deny", rb_seccomp_deny, 1);

    rb_define_alloc_func(cSeccomp, rb_seccomp_allocate);

    eSeccompError=rb_define_class("SeccompError", rb_eRuntimeError);
}
