#define PERL_NO_GET_CONTEXT
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#include "fastcgi.h"

#define FCGI_GET_UINT8(s,m)       \
    ((U8)(s)->m)

#define FCGI_GET_UINT16(s,m)      \
    (  ((U16)(s)->m ## B1 <<  8)  \
     | ((U16)(s)->m ## B0      ))

#define FCGI_GET_UINT32(s,m)      \
    (  ((U32)(s)->m ## B3 << 24)  \
     | ((U32)(s)->m ## B2 << 16)  \
     | ((U32)(s)->m ## B1 <<  8)  \
     | ((U32)(s)->m ## B0      ))

#define FCGI_SET_UINT8(s,m,v)                                   \
    STMT_START {                                                \
        (s)->m       = (unsigned char) (((v)      ) & 0xFF);    \
    } STMT_END

#define FCGI_SET_UINT32(s,m,v)                                  \
    STMT_START {                                                \
        (s)->m ## B3 = (unsigned char) (((v) >> 24) & 0xFF);    \
        (s)->m ## B2 = (unsigned char) (((v) >> 16) & 0xFF);    \
        (s)->m ## B1 = (unsigned char) (((v) >>  8) & 0xFF);    \
        (s)->m ## B0 = (unsigned char) (((v)      ) & 0xFF);    \
    } STMT_END

#define FCGI_SET_UINT16(s,m,v)                                  \
    STMT_START {                                                \
        (s)->m ## B1 = (unsigned char) (((v) >>  8) & 0xFF);    \
        (s)->m ## B0 = (unsigned char) (((v)      ) & 0xFF);    \
    } STMT_END

#define FCGI_SEGMENT_LEN                                        \
    (32768 - FCGI_HEADER_LEN)

#define FCGI_PADDING_LEN(content_length)                        \
    ((8 - (content_length % 8)) % 8)

#define FCGI_RECORD_LEN(content_length)                         \
    (FCGI_HEADER_LEN + content_length + FCGI_PADDING_LEN(content_length))

#define ERRMSG_OCTETS       "FastCGI: Insufficient number of octets to parse %s"
#define ERRMSG_MALFORMED    "FastCGI: Malformed record %s"
#define ERRMSG_VERSION      "FastCGI: Protocol version mismatch (0x%.2X)"
#define ERRMSG_OCTETS_LE    "Invalid Argument: '%s' cannot exceed %u octets in length"

#define hv_store_const(hv, key, value)                  \
STMT_START {                                            \
    SV *sv = value;                                     \
    if (!hv_store(hv, key, sizeof(key) - 1, sv, 0)) {   \
        SvREFCNT_dec(sv);                               \
        croak("FastCGI: panic: hv_store(%s)", key);     \
    }                                                   \
} STMT_END

#define hv_store_const_uv(hv, key, value)               \
    hv_store_const(hv, key, newSVuv(value))

static void
nfc_init_header(FCGI_Header *hdr, U8 type, U16 rid, U16 clen, U8 plen) {
    FCGI_SET_UINT8(hdr, version, FCGI_VERSION_1);
    FCGI_SET_UINT8(hdr, type, type);
    FCGI_SET_UINT16(hdr, requestId, rid);
    FCGI_SET_UINT16(hdr, contentLength, clen);
    FCGI_SET_UINT8(hdr, paddingLength, plen);
    FCGI_SET_UINT8(hdr, reserved, 0);
}

static void
nfc_init_begin_request_body(FCGI_BeginRequestBody *body, U16 role, U8 flags) {
    FCGI_SET_UINT16(body, role, role);
    FCGI_SET_UINT8(body, flags, flags);
    memset(body->reserved, 0, sizeof(body->reserved));
}

static void
nfc_init_end_request_body(FCGI_EndRequestBody *body, U32 astatus, U8 pstatus) {
    FCGI_SET_UINT32(body, appStatus, astatus);
    FCGI_SET_UINT8(body, protocolStatus, pstatus);
    memset(body->reserved, 0, sizeof(body->reserved));
}

static void
nfc_init_unknown_type_body(FCGI_UnknownTypeBody *body, U8 type) {
    FCGI_SET_UINT8(body, type, type);
    memset(body->reserved, 0, sizeof(body->reserved));
}

static void
nfc_init_begin_request_record(FCGI_BeginRequestRecord *rec, U16 rid, U16 role, U8 flags) {
    nfc_init_header(&(rec->header), FCGI_BEGIN_REQUEST, rid, (U16)sizeof(rec->body), 0);
    nfc_init_begin_request_body(&(rec->body), role, flags);
}

static void
nfc_init_end_request_record(FCGI_EndRequestRecord *rec, U16 rid, U32 astatus, U8 pstatus) {
    nfc_init_header(&(rec->header), FCGI_END_REQUEST, rid, (U16)sizeof(rec->body), 0);
    nfc_init_end_request_body(&(rec->body), astatus, pstatus);
}

static void
nfc_init_unknown_type_record(FCGI_UnknownTypeRecord *rec, U8 type) {
    nfc_init_header(&(rec->header), FCGI_UNKNOWN_TYPE, FCGI_NULL_REQUEST_ID, (U16)sizeof(rec->body), 0);
    nfc_init_unknown_type_body(&(rec->body), type);
}

static void
nfc_build_params(pTHX_ SV *dsv, HV *params) {
    char *cur = SvPVX(dsv);
    char *end = SvPVX(dsv) + SvLEN(dsv) - 1;
    const char *key, *val;
    STRLEN klen, vlen, need;
    HE *he;
    SV *sv;

    hv_iterinit(params);
    while ((he = hv_iternext(params))) {

        if (HeKLEN(he) == HEf_SVKEY) {
            sv = HeKEY_sv(he);
            SvGETMAGIC(sv);
            if (DO_UTF8(sv))
                sv_utf8_downgrade(sv, 0);
            key = SvPV_nomg_const(sv, klen);
        }
        else
            key = HePV(he, klen);

        if (SvMAGICAL(params))
            sv = hv_iterval(params, he);
        else
            sv = HeVAL(he);

        SvGETMAGIC(sv);
        if (SvOK(sv)) {
            if (DO_UTF8(sv))
                sv_utf8_downgrade(sv, 0);
            val = SvPV_nomg_const(sv, vlen);
        }
        else
            val = NULL, vlen = 0;

        assert(klen <= 0x7FFFFFFF);
        assert(vlen <= 0x7FFFFFFF);

        need = (klen < 0x80 ? 1 : 4) + (vlen < 0x80 ? 1 : 4) + klen + vlen;

        if (cur + need > end) {
            STRLEN off = cur - SvPVX(dsv);
            SvGROW(dsv, off + (need < (off >> 2) ? (off >> 2) : need) + 1);
            cur = SvPVX(dsv) + off;
            end = SvPVX(dsv) + SvLEN(dsv) - 1;
        }

        if (klen < 0x80) {
            *cur++ = (char)(klen & 0xFF);
        }
        else {
            *cur++ = (char)(((klen >> 24) | 0x80) & 0xFF);
            *cur++ = (char)((klen >> 16) & 0xFF);
            *cur++ = (char)((klen >> 8) & 0xFF);
            *cur++ = (char)(klen & 0xFF);
        }

        if (vlen < 0x80) {
            *cur++ = (char)(vlen & 0xFF);
        }
        else {
            *cur++ = (char)(((vlen >> 24 | 0x80)) & 0xFF);
            *cur++ = (char)((vlen >> 16) & 0xFF);
            *cur++ = (char)((vlen >> 8) & 0xFF);
            *cur++ = (char)(vlen & 0xFF);
        }

        if (klen) {
            memcpy(cur, key, klen);
            cur += klen;
        }

        if (vlen) {
            memcpy(cur, val, vlen);
            cur += vlen;
        }
    }

    SvCUR_set(dsv, cur - SvPVX(dsv));
    (void)SvPOK_only(dsv);
    *SvEND(dsv) = '\0';
}

static void
nfc_parse_params(pTHX_ const char *p, STRLEN len, HV *params) {
    const char *pe = p + len;
    U32 klen, vlen;
    SV *val;

    while (p < pe) {
        klen = (unsigned char)*p++;
        if (klen > 0x7F) {
            if (p + 3 > pe)
                goto bad;
            klen  =  (klen & 0x7F) << 24;
            klen |= ((unsigned char)*p++ << 16);
            klen |= ((unsigned char)*p++ <<  8);
            klen |= ((unsigned char)*p++ <<  0);
        }
        if (p + 1 > pe)
            goto bad;
        vlen = (unsigned char)*p++;
        if (vlen > 0x7F) {
            if (p + 3 > pe)
                goto bad;
            vlen  =  (vlen & 0x7F) << 24;
            vlen |= ((unsigned char)*p++ << 16);
            vlen |= ((unsigned char)*p++ <<  8);
            vlen |= ((unsigned char)*p++ <<  0);
        }
        if (p + klen + vlen > pe)
            goto bad;

        val = newSVpvn(p + klen, vlen);
        if (!hv_store(params, p, (I32)klen, val, 0)) {
            SvREFCNT_dec(val);
            croak("FastCGI: panic hv_store(FCGI_NameValuePair)");
        }
        p += klen + vlen;
    }

    return;
  bad:
    croak(ERRMSG_OCTETS, "FCGI_NameValuePair");
}

static bool
nfc_check_params(const char *p, STRLEN len) {
    const char *pe = p + len;
    U32 klen, vlen;

    while (p < pe) {
        klen = (unsigned char)*p++;
        if (klen > 0x7F) {
            if (p + 3 > pe)
                return FALSE;
            klen  =  (klen & 0x7F) << 24;
            klen |= ((unsigned char)*p++ << 16);
            klen |= ((unsigned char)*p++ <<  8);
            klen |= ((unsigned char)*p++ <<  0);
        }
        if (p + 1 > pe)
            return FALSE;
        vlen = (unsigned char)*p++;
        if (vlen > 0x7F) {
            if (p + 3 > pe)
                return FALSE;
            vlen  =  (vlen & 0x7F) << 24;
            vlen |= ((unsigned char)*p++ << 16);
            vlen |= ((unsigned char)*p++ <<  8);
            vlen |= ((unsigned char)*p++ <<  0);
        }
        if ((p += klen + vlen) > pe)
            return FALSE;
    }
    return TRUE;
}

static SV *
nfc_parse_record_body(pTHX_ U8 type, U16 request_id, const char *c, STRLEN clen) {
    HV *hv = newHV();
    SV *rv = sv_2mortal(newRV_noinc((SV*)hv));
    static const char name [12][27] = {
        "0x00",
        "FCGI_BeginRequestRecord",
        "FCGI_AbortRequestRecord",
        "FCGI_EndRequestRecord",
        "FCGI_ParamsRecord",
        "FCGI_StdinRecord",
        "FCGI_StdoutRecord",
        "FCGI_StderrRecord",
        "FCGI_DataRecord",
        "FCGI_GetValuesRecord",
        "FCGI_GetValuesResultRecord",
        "FCGI_UnknownTypeRecord"
    };

    if (clen > 0xFFFF)
        croak(ERRMSG_OCTETS_LE, "content", 0xFFFF);

    hv_store_const_uv(hv, "type", type);
    hv_store_const_uv(hv, "request_id", request_id);

    switch (type) {
        case FCGI_BEGIN_REQUEST: {
            const FCGI_BeginRequestBody *body;

            if (request_id == FCGI_NULL_REQUEST_ID || clen != sizeof(FCGI_BeginRequestBody))
                croak(ERRMSG_MALFORMED, name[type]);

            body = (const FCGI_BeginRequestBody *)c;
            hv_store_const_uv(hv, "role", FCGI_GET_UINT16(body, role));
            hv_store_const_uv(hv, "flags", body->flags);
            break;
        }
        case FCGI_ABORT_REQUEST: {
            if (request_id == FCGI_NULL_REQUEST_ID || clen != 0)
                croak(ERRMSG_MALFORMED, name[type]);
            break;
        }
        case FCGI_END_REQUEST: {
            const FCGI_EndRequestBody *body;

            if (request_id == FCGI_NULL_REQUEST_ID || clen != sizeof(FCGI_EndRequestBody))
                croak(ERRMSG_MALFORMED, name[type]);

            body = (const FCGI_EndRequestBody *)c;
            hv_store_const_uv(hv, "app_status", FCGI_GET_UINT32(body, appStatus));
            hv_store_const_uv(hv, "protocol_status", body->protocolStatus);
            break;
        }
        case FCGI_PARAMS:
        case FCGI_STDIN:
        case FCGI_STDOUT:
        case FCGI_STDERR:
        case FCGI_DATA: {
            if (request_id == FCGI_NULL_REQUEST_ID)
                croak(ERRMSG_MALFORMED, name[type]);

            hv_store_const(hv, "content", newSVpvn(c, clen));
            break;
        }
        case FCGI_GET_VALUES:
        case FCGI_GET_VALUES_RESULT: {
            HV *values;

            if (request_id != FCGI_NULL_REQUEST_ID)
                croak(ERRMSG_MALFORMED, name[type]);

            values = newHV();
            hv_store_const(hv, "values", newRV_noinc((SV*)values));

            if (clen)
                nfc_parse_params(aTHX_ c, clen, values);
            break;
        }
        case FCGI_UNKNOWN_TYPE: {
            const FCGI_UnknownTypeBody *body;

            if (request_id != FCGI_NULL_REQUEST_ID || clen != sizeof(FCGI_UnknownTypeBody))
                croak(ERRMSG_MALFORMED, name[type]);

            body = (const FCGI_UnknownTypeBody *)c;
            hv_store_const_uv(hv, "unknown_type", body->type);
            break;
        }
        default: {
            if (clen)
                hv_store_const(hv, "content", newSVpvn(c, clen));
            break;
        }
    }
    return rv;
}

static STRLEN
nfc_put_header(char *dst, U8 type, U16 id, U16 clen, U8 plen) {
    nfc_init_header((FCGI_Header *)dst, type, id, clen, plen);
    return sizeof(FCGI_Header);
}

static STRLEN
nfc_put_record(char *dst, U8 type, U16 id, const char *src, U16 clen) {
    U8 plen = FCGI_PADDING_LEN(clen);
    char *s = dst;

    dst += nfc_put_header(dst, type, id, clen, plen);

    if (clen) {
        memcpy(dst, src, clen);
        dst += clen;
        if (plen) {
            memset(dst, 0, plen);
            dst += plen;
        }
    }
    return dst - s;
}

static void
nfc_put_stream(char *dst, U8 type, U16 id, const char *src, STRLEN len, bool term) {
    if (len > FCGI_SEGMENT_LEN) {
        FCGI_Header header;

        nfc_init_header(&header, type, id, FCGI_SEGMENT_LEN, 0);
        while (len >= FCGI_SEGMENT_LEN) {
            memcpy(dst, &header, sizeof(FCGI_Header));
            dst += sizeof(FCGI_Header);
            memcpy(dst, src, FCGI_SEGMENT_LEN);
            dst += FCGI_SEGMENT_LEN;
            src += FCGI_SEGMENT_LEN;
            len -= FCGI_SEGMENT_LEN;
        }
        if (len)
            dst += nfc_put_record(dst, type, id, src, (U16)len);
    }
    else {
        dst += nfc_put_record(dst, type, id, src, (U16)len);
    }
    if (term)
        dst += nfc_put_header(dst, type, id, 0, 0);
}


#define init_header                     nfc_init_header
#define init_begin_request_body         nfc_init_begin_request_body
#define init_begin_request_record       nfc_init_begin_request_record
#define init_end_request_body           nfc_init_end_request_body
#define init_end_request_record         nfc_init_end_request_record
#define init_unknown_type_body          nfc_init_unknown_type_body
#define init_unknown_type_record        nfc_init_unknown_type_record
#define put_header                      nfc_put_header
#define put_record                      nfc_put_record
#define put_stream                      nfc_put_stream
#define build_params(a, b)              nfc_build_params(aTHX_ a, b)
#define parse_params(a, b, c)           nfc_parse_params(aTHX_ a, b, c)
#define check_params(a, b)              nfc_check_params(a, b)
#define parse_record_body(a, b, c, d)   nfc_parse_record_body(aTHX_ a, b, c, d)

#define undef &PL_sv_undef

MODULE = Net::FastCGI::XS   PACKAGE = Net::FastCGI::Protocol::XS

PROTOTYPES: DISABLE

void
build_header(type, request_id, content_length, padding_length)
    U8  type
    U16 request_id
    U16 content_length
    U8  padding_length
  PREINIT:
    dXSTARG;
  PPCODE:
    SvUPGRADE(TARG, SVt_PV);
    SvGROW(TARG, sizeof(FCGI_Header) + 1);
    init_header((FCGI_Header *)SvPVX(TARG), type, request_id, content_length, padding_length);
    SvCUR_set(TARG, sizeof(FCGI_Header));
    (void)SvPOK_only(TARG);
    *SvEND(TARG) = '\0';
    PUSHTARG;

void
parse_header(octets)
    SV *octets
  INIT:
    const FCGI_Header *header;
    const char *buf = NULL;
    STRLEN len = 0;
  PPCODE:
    SvGETMAGIC(octets);
    if (SvOK(octets)) {
        if (DO_UTF8(octets))
            sv_utf8_downgrade(octets, 0);
        buf = SvPV_nomg_const(octets, len);
    }
    if (len < sizeof(FCGI_Header))
        croak(ERRMSG_OCTETS, "FCGI_Header");

    header = (const FCGI_Header *)buf;
    if (header->version != FCGI_VERSION_1)
        croak(ERRMSG_VERSION, header->version);

    if (GIMME == G_ARRAY) {
        EXTEND(SP, 4);
        mPUSHu(header->type);
        mPUSHu(FCGI_GET_UINT16(header, requestId));
        mPUSHu(FCGI_GET_UINT16(header, contentLength));
        mPUSHu(header->paddingLength);
    }
    else {
        HV *hv = newHV();
        SV *rv = sv_2mortal(newRV_noinc((SV*)hv));
        hv_store_const_uv(hv, "type", header->type);
        hv_store_const_uv(hv, "request_id", FCGI_GET_UINT16(header, requestId));
        hv_store_const_uv(hv, "content_length", FCGI_GET_UINT16(header, contentLength));
        hv_store_const_uv(hv, "padding_length", header->paddingLength);
        PUSHs(rv);
    }

void
build_params(params)
    HV *params
  PREINIT:
    dXSTARG;
  PPCODE:
    SvUPGRADE(TARG, SVt_PV);
    SvGROW(TARG, 512 + 1);
    build_params(TARG, params);
    PUSHTARG;

void
parse_params(octets)
    SV *octets
  PREINIT:
    const char *buf = NULL;
    STRLEN len = 0;
    HV *hv = newHV();
    SV *rv = sv_2mortal(newRV_noinc((SV*)hv));
  PPCODE:
    SvGETMAGIC(octets);
    if (SvOK(octets)) {
        if (DO_UTF8(octets))
            sv_utf8_downgrade(octets, 0);
        buf = SvPV_nomg_const(octets, len);
    }
    if (len)
        parse_params(buf, len, hv);
    PUSHs(rv);

void
check_params(octets)
    SV *octets
  PREINIT:
    const char *buf = NULL;
    STRLEN len = 0;
  PPCODE:
    SvGETMAGIC(octets);
    if (SvOK(octets)) {
        if (DO_UTF8(octets))
            sv_utf8_downgrade(octets, 0);
        buf = SvPV_nomg_const(octets, len);
        PUSHs(boolSV(check_params(buf, len)));
    }
    else
        PUSHs(&PL_sv_no);

void
build_record(type, request_id, content=undef)
    U8  type
    U16 request_id
    SV *content
  PREINIT:
    dXSTARG;
    const char *cp = NULL;
    STRLEN record_len, content_len = 0;
  PPCODE:
    SvGETMAGIC(content);
    if (SvOK(content)) {
        if (DO_UTF8(content))
            sv_utf8_downgrade(content, 0);
        cp = SvPV_nomg_const(content, content_len);
        if (content_len > 0xFFFF)
            croak(ERRMSG_OCTETS_LE, "content", 0xFFFF);
    }
    record_len = FCGI_RECORD_LEN(content_len);
    SvUPGRADE(TARG, SVt_PV);
    SvGROW(TARG, record_len + 1);
    put_record(SvPVX(TARG), type, request_id, cp, (U16)content_len);
    SvCUR_set(TARG, record_len);
    (void)SvPOK_only(TARG);
    *SvEND(TARG) = '\0';
    PUSHTARG;

void
parse_record(octets)
    SV *octets
  PREINIT:
    const char *buf = NULL;
    STRLEN content_len, len = 0;
    const FCGI_Header *header;
  PPCODE:
    SvGETMAGIC(octets);
    if (SvOK(octets)) {
        if (DO_UTF8(octets))
            sv_utf8_downgrade(octets, 0);
        buf = SvPV_nomg_const(octets, len);
    }
    if (len < sizeof(FCGI_Header))
        croak(ERRMSG_OCTETS, "FCGI_Record");

    header = (const FCGI_Header *)buf;
    if (header->version != FCGI_VERSION_1)
        croak(ERRMSG_VERSION, header->version);

    buf += sizeof(FCGI_Header);
    len -= sizeof(FCGI_Header);

    content_len = FCGI_GET_UINT16(header, contentLength);
    if (len < content_len)
        croak(ERRMSG_OCTETS, "FCGI_Record");

    if (GIMME == G_ARRAY) {
        dXSTARG;
        EXTEND(SP, 2);
        mPUSHu(header->type);
        mPUSHu(FCGI_GET_UINT16(header, requestId));
        PUSHp(buf, content_len);
    }
    else {
        U16 request_id = FCGI_GET_UINT16(header, requestId);
        PUSHs(parse_record_body(header->type, request_id, buf, content_len));
    }

void
parse_record_body(type, request_id, content)
    U8  type
    U16 request_id
    SV *content
  PREINIT:
    const char *buf = "";
    STRLEN content_len = 0;
  PPCODE:
    SvGETMAGIC(content);
    if (SvOK(content)) {
        if (DO_UTF8(content))
            sv_utf8_downgrade(content, 0);
        buf = SvPV_nomg_const(content, content_len);
    }
    PUSHs(parse_record_body(type, request_id, buf, content_len));

void
build_stream(type, request_id, content=undef, terminate=FALSE)
    U8  type
    U16 request_id
    SV *content
    bool terminate
  PREINIT:
    dXSTARG;
    const char *buf = NULL;
    STRLEN stream_len, content_len = 0;
    UV nrecords;
  PPCODE:
    SvGETMAGIC(content);
    if (SvOK(content)) {
        if (DO_UTF8(content))
            sv_utf8_downgrade(content, 0);
        buf = SvPV_nomg_const(content, content_len);
        if (content_len > 0xFFFF)
            croak(ERRMSG_OCTETS_LE, "content", 0xFFFF);
    }
    nrecords = (content_len + FCGI_SEGMENT_LEN - 1) / FCGI_SEGMENT_LEN;
    if (terminate)
        nrecords++;
    stream_len = nrecords * FCGI_HEADER_LEN;
    stream_len += FCGI_PADDING_LEN(content_len);
    stream_len += content_len;
    SvUPGRADE(TARG, SVt_PV);
    SvGROW(TARG, stream_len + 1);
    if (stream_len)
        put_stream(SvPVX(TARG), type, request_id, buf, content_len, terminate);
    SvCUR_set(TARG, stream_len);
    (void)SvPOK_only(TARG);
    *SvEND(TARG) = '\0';
    PUSHTARG;

void
build_begin_request_body(role, flags)
    U16 role
    U8  flags
  PREINIT:
    dXSTARG;
  PPCODE:
    SvUPGRADE(TARG, SVt_PV);
    SvGROW(TARG, sizeof(FCGI_BeginRequestBody) + 1);
    init_begin_request_body((FCGI_BeginRequestBody *)SvPVX(TARG), role, flags);
    SvCUR_set(TARG, sizeof(FCGI_BeginRequestBody));
    (void)SvPOK_only(TARG);
    *SvEND(TARG) = '\0';
    PUSHTARG;

void
parse_begin_request_body(octets)
    SV *octets
  INIT:
    const FCGI_BeginRequestBody *body;
    const char *buf = NULL;
    STRLEN len = 0;
  PPCODE:
    SvGETMAGIC(octets);
    if (SvOK(octets)) {
        if (DO_UTF8(octets))
            sv_utf8_downgrade(octets, 0);
        buf = SvPV_nomg_const(octets, len);
    }
    if (len < sizeof(FCGI_BeginRequestBody))
        croak(ERRMSG_OCTETS, "FCGI_BeginRequestBody");

    body = (const FCGI_BeginRequestBody *)buf;
    EXTEND(SP, 2);
    mPUSHu(FCGI_GET_UINT16(body, role));
    mPUSHu(body->flags);

void
build_begin_request_record(request_id, role, flags)
    U16 request_id
    U16 role
    U8  flags
  PREINIT:
    dXSTARG;
  PPCODE:
    SvUPGRADE(TARG, SVt_PV);
    SvGROW(TARG, sizeof(FCGI_BeginRequestRecord) + 1);
    init_begin_request_record((FCGI_BeginRequestRecord *)SvPVX(TARG), request_id, role, flags);
    SvCUR_set(TARG, sizeof(FCGI_BeginRequestRecord));
    (void)SvPOK_only(TARG);
    *SvEND(TARG) = '\0';
    PUSHTARG;

void
build_end_request_body(app_status, protocol_status)
    U32 app_status
    U8  protocol_status
  PREINIT:
    dXSTARG;
  PPCODE:
    SvUPGRADE(TARG, SVt_PV);
    SvGROW(TARG, sizeof(FCGI_EndRequestBody) + 1);
    init_end_request_body((FCGI_EndRequestBody *)SvPVX(TARG), app_status, protocol_status);
    SvCUR_set(TARG, sizeof(FCGI_EndRequestBody));
    (void)SvPOK_only(TARG);
    *SvEND(TARG) = '\0';
    PUSHTARG;

void
parse_end_request_body(octets)
    SV *octets
  INIT:
    const FCGI_EndRequestBody *body;
    const char *buf = NULL;
    STRLEN len = 0;
  PPCODE:
    SvGETMAGIC(octets);
    if (SvOK(octets)) {
        if (DO_UTF8(octets))
            sv_utf8_downgrade(octets, 0);
        buf = SvPV_nomg_const(octets, len);
    }
    if (len < sizeof(FCGI_EndRequestBody))
        croak(ERRMSG_OCTETS, "FCGI_EndRequestBody");

    body = (const FCGI_EndRequestBody *)buf;
    EXTEND(SP, 2);
    mPUSHu(FCGI_GET_UINT32(body, appStatus));
    mPUSHu(body->protocolStatus);

void
build_end_request_record(request_id, app_status, protocol_status)
    U16 request_id
    U32 app_status
    U8  protocol_status
  PREINIT:
    dXSTARG;
  PPCODE:
    SvUPGRADE(TARG, SVt_PV);
    SvGROW(TARG, sizeof(FCGI_EndRequestRecord) + 1);
    init_end_request_record((FCGI_EndRequestRecord *)SvPVX(TARG), request_id, app_status, protocol_status);
    SvCUR_set(TARG, sizeof(FCGI_EndRequestRecord));
    (void)SvPOK_only(TARG);
    *SvEND(TARG) = '\0';
    PUSHTARG;

void
build_unknown_type_body(type)
    U8 type
  PREINIT:
    dXSTARG;
  PPCODE:
    SvUPGRADE(TARG, SVt_PV);
    SvGROW(TARG, sizeof(FCGI_UnknownTypeBody) + 1);
    init_unknown_type_body((FCGI_UnknownTypeBody *)SvPVX(TARG), type);
    SvCUR_set(TARG, sizeof(FCGI_UnknownTypeBody));
    (void)SvPOK_only(TARG);
    *SvEND(TARG) = '\0';
    PUSHTARG;

void
parse_unknown_type_body(octets)
    SV *octets
  INIT:
    const FCGI_UnknownTypeBody *body;
    const char *buf = NULL;
    STRLEN len = 0;
  PPCODE:
    SvGETMAGIC(octets);
    if (SvOK(octets)) {
        if (DO_UTF8(octets))
            sv_utf8_downgrade(octets, 0);
        buf = SvPV_nomg_const(octets, len);
    }
    if (len < sizeof(FCGI_UnknownTypeBody))
        croak(ERRMSG_OCTETS, "FCGI_UnknownTypeBody");

    body = (const FCGI_UnknownTypeBody *)buf;
    mPUSHu(body->type);

void
build_unknown_type_record(type)
    U8 type
  PREINIT:
    dXSTARG;
  PPCODE:
    SvUPGRADE(TARG, SVt_PV);
    SvGROW(TARG, sizeof(FCGI_UnknownTypeRecord) + 1);
    init_unknown_type_record((FCGI_UnknownTypeRecord *)SvPVX(TARG), type);
    SvCUR_set(TARG, sizeof(FCGI_UnknownTypeRecord));
    (void)SvPOK_only(TARG);
    *SvEND(TARG) = '\0';
    PUSHTARG;

void
get_record_length(octets)
    SV *octets
  PREINIT:
    dXSTARG;
    const char *buf = NULL;
    STRLEN len = 0;
    UV record_len = 0;
  PPCODE:
    SvGETMAGIC(octets);
    if (SvOK(octets)) {
        if (DO_UTF8(octets))
            sv_utf8_downgrade(octets, 0);
        buf = SvPV_nomg_const(octets, len);
    }
    if (len >= sizeof(FCGI_Header)) {
        const FCGI_Header *header = (const FCGI_Header *)buf;
        record_len = sizeof(FCGI_Header)
                   + FCGI_GET_UINT16(header, contentLength)
                   + FCGI_GET_UINT8(header, paddingLength);
    }
    PUSHu(record_len);

void
is_known_type(type)
    U8 type
  PPCODE:
    PUSHs(boolSV(type > 0 && type <= FCGI_MAXTYPE));

void
is_discrete_type(type)
    U8 type
  PPCODE:
    switch (type) {
        case FCGI_BEGIN_REQUEST:
        case FCGI_ABORT_REQUEST:
        case FCGI_END_REQUEST:
        case FCGI_GET_VALUES:
        case FCGI_GET_VALUES_RESULT:
        case FCGI_UNKNOWN_TYPE:
            PUSHs(&PL_sv_yes);
            break;
        default:
            PUSHs(&PL_sv_no);
    }

void
is_management_type(type)
    U8 type
  PPCODE:
    switch (type) {
        case FCGI_GET_VALUES:
        case FCGI_GET_VALUES_RESULT:
        case FCGI_UNKNOWN_TYPE:
            PUSHs(&PL_sv_yes);
            break;
        default:
            PUSHs(&PL_sv_no);
    }

void
is_stream_type(type)
    U8 type
  PPCODE:
    switch (type) {
        case FCGI_PARAMS:
        case FCGI_STDIN:
        case FCGI_STDOUT:
        case FCGI_STDERR:
        case FCGI_DATA:
            PUSHs(&PL_sv_yes);
            break;
        default:
            PUSHs(&PL_sv_no);
    }

void
get_type_name(type)
    U8 type
  PREINIT:
    dXSTARG;
    static const char name [12][23] = {
        "0x00",
        "FCGI_BEGIN_REQUEST",
        "FCGI_ABORT_REQUEST",
        "FCGI_END_REQUEST",
        "FCGI_PARAMS",
        "FCGI_STDIN",
        "FCGI_STDOUT",
        "FCGI_STDERR",
        "FCGI_DATA",
        "FCGI_GET_VALUES",
        "FCGI_GET_VALUES_RESULT",
        "FCGI_UNKNOWN_TYPE"
    };
  PPCODE:
    if (type <= FCGI_UNKNOWN_TYPE)
        PUSHp(name[type], strlen(name[type]));
    else
        mPUSHs(newSVpvf("0x%.2X", type));

void
get_role_name(role)
    U16 role
  PREINIT:
    dXSTARG;
    static const char name [4][16] = {
        "0x0000",
        "FCGI_RESPONDER",
        "FCGI_AUTHORIZER",
        "FCGI_FILTER"
    };
  PPCODE:
    if (role <= FCGI_FILTER)
        PUSHp(name[role], strlen(name[role]));
    else
        mPUSHs(newSVpvf("0x%.4X", role));

void
get_protocol_status_name(status)
    U8 status
  PREINIT:
    dXSTARG;
    static const char name [4][22] = {
        "FCGI_REQUEST_COMPLETE",
        "FCGI_CANT_MPX_CONN",
        "FCGI_OVERLOADED",
        "FCGI_UNKNOWN_ROLE"
    };
  PPCODE:
    if (status <= FCGI_UNKNOWN_ROLE)
        PUSHp(name[status], strlen(name[status]));
    else
        mPUSHs(newSVpvf("0x%.2X", status));

