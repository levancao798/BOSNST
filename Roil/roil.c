/*
 *  $Id: roil.c,v 1.1 2002/04/11 04:42:06 route Exp $
 *
 *  Building Open Source Network Security Tools
 *  roil.c - openssl example code
 *
 *  Copyright (c) 2002 Mike D. Schiffman <mike@infonexus.com>
 *  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */
 
#include "./roil.h"

int
main(int argc, char **argv)
{
    int c;
    u_char flags;
    char *md;
    char *ea;
    FILE *filename;
    char errbuf[256];
    struct roil_pack *rp;

    printf("Roil 1.0 [little encryption tool]\n");

    flags = 0;
    md = NULL;
    ea = NULL;
    filename = NULL;
    while ((c = getopt(argc, argv, "de:hm:")) != EOF)
    {
        switch (c)
        {
            case 'd':
                flags |= DECRYPT;
                break;
            case 'e':
                ea = optarg;
                flags |= ENCRYPT;
                break;
            case 'h':
                usage(argv[0]);
                exit(EXIT_SUCCESS);
                break;
            case 'm':
                md = optarg;
                flags |= MD;
                break;
            default:
                usage(argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (flags == 0 || (flags & ENCRYPT && flags & DECRYPT))
    {
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    if (argc - optind != 1)
    {
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    rp = roil_init(argv[optind], flags, md, ea, errbuf);
    if (rp == NULL)
    {
        fprintf(stderr, "roil_init(): %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    roil(rp);
    roil_destroy(rp);

    return (EXIT_SUCCESS);
}


struct roil_pack *
roil_init(char *filename, u_char flags, char *md, char *ea, char *errbuf)
{
    struct roil_pack *rp;

    /* grab memory for our monolithic structure */
    rp = malloc(sizeof (struct roil_pack));
    if (rp == NULL)
    {
        sprintf(errbuf, strerror(errno));
        return (NULL);
    }

    /* open the input file */
    rp->fd_in = open(filename, O_RDWR);
    if (rp->fd_in == -1)
    {
        sprintf(errbuf, "can't open input file \"%s\" %s",
                filename, strerror(errno));
        roil_destroy(rp);
        return (NULL);
    }

    /* save the filename */
    strncpy(rp->fn_in, filename, sizeof (rp->fn_in) - 1);

    rp->flags = flags;

    /* copy over the message digest name */
    if (md)
    {
        strncpy(rp->md, md, 10);
    }

    /* copy over the message digest name */
    if (ea)
    {
        strncpy(rp->ea, ea, 10);
    }

    return (rp);
}


void
roil_destroy(struct roil_pack *rp)
{
    if (rp)
    {
        if (rp->fd_in)
        {
            close (rp->fd_in);
        }
        if (rp->fd_out)
        {
            close (rp->fd_out);
        }
        free(rp);
        EVP_cleanup();
    }
}


int
open_outputfile(struct roil_pack *rp)
{
    int n;

    n = strlen(rp->fn_in);
    strcpy(rp->fn_out, rp->fn_in);

    if (rp->flags & ENCRYPT)
    {
        if (!(n + 4 < 100))
        {
            /* filename too long */
            sprintf(rp->errbuf, "open_outputfile(): filename too long\n");
            return (-1);
        }
        strcpy(rp->fn_out + n, ".roil");
    }
    else
    {
        if (n < 4)
        {
            /* filename too short */
            sprintf(rp->errbuf,
                    "open_outputfile(): filename too short\n");
            return (-1);
        }
        if (strncmp(&rp->fn_out[n - 5], ".roil", 5) == 0)
        {
            /* cut ".roil" from filename */
            rp->fn_out[n - 5] = 0;
        }
        else
        {
            /* unknown suffix / filename */
            sprintf(rp->errbuf, "open_outputfile(): unknown suffix\n");
            return (-1);
        }
    }

    /* open the file */
    rp->fd_out = open(rp->fn_out, O_CREAT | O_WRONLY);
    if (rp->fd_out == -1)
    {
        sprintf(rp->errbuf, "open_outputfile(): %s\n", strerror(errno));
        return (-1);
    }

    /* set a umask of 600 */
    if (fchmod(rp->fd_out, 0600) == -1)
    {
        sprintf(rp->errbuf, "open_outputfile(): %s\n", strerror(errno));
        return (-1);
    }
    return (1);
}


void
roil(struct roil_pack *rp)
{
    int n, len;
    u_char *p;

    if (rp->flags & MD)
    {
        /*
         *  We're going to be digesting a file here.  The other case
         *  when we would be digesting a user's passphrase to create a
         *  sufficiently long key for encryption or decryption comes
         *  into play from within roil_cipher() and never here.
         */
        rp->flags |= MD_FROMFILE;

        /*
         *  Digest the file contained in rp.  Upon success, the function
         *  will return a pointer to a static buffer containing the hash
         *  and the length will be written to len.  Upon failure p will
         *  point to a NULL buffer and rp->errbuf will contain the
         *  reason.
         */
        p = roil_digest(rp, &len);
        if (p == NULL)
        {
            fprintf(stderr, "roil_digest(): %s", rp->errbuf);
            return;
        }
        printf("%s message digest of %s: ", rp->md, rp->fn_in);
        for (n = 0; n < len; n++)
        {
            printf("%02x", p[n]);
        }
        printf("\n");
    }
    else if ((rp->flags & ENCRYPT) || (rp->flags & DECRYPT))
    {
        /*
         *  Encrypt or decrypt the file contained in rp.  Upon succes, the 
         *  function will return 1; upon failure the function will return 
         *  -1 and rp->errbuf will contain the reason.
         */
        if (roil_cipher(rp) == -1)
        {
            fprintf(stderr, "roil_cipher(): %s", rp->errbuf);
            return;
        }
    }
}


u_char *
roil_digest(struct roil_pack *rp, int *digest_len)
{
    int n;
    const EVP_MD *md;
    u_char buf[BUF_SIZE];
    EVP_MD_CTX md_context;
    static u_char digest[EVP_MAX_MD_SIZE];

    /* add all available digest algorithms to the hash table */
    OpenSSL_add_all_digests();

    /* load and verify the digest specified at the command line */
    md = EVP_get_digestbyname(rp->md);
    if (md == NULL)
    {
        snprintf(rp->errbuf, ERRBUF_SIZE, "unknown digest %s\n", rp->md);
        goto bad;
    }

    /*
     *  Initialize the md context.  Really all this does is zero out the
     *  structure.
     */
    EVP_MD_CTX_init(&md_context);

    /* initialize the md algorithm */
    if (EVP_DigestInit(&md_context, md) == 0)
    {
        snprintf(rp->errbuf, ERRBUF_SIZE, "EVP_DigestInit() failed\n");
        goto bad;
    }

    memset (digest, 0, sizeof (digest));
    if (rp->flags & MD_FROMFILE)
    {
        /*
         *  Digest the file.  Read in a block of data into buf and
         *  process it with the md algorithm.
         */
        while ((n = read(rp->fd_in, buf, sizeof (buf))) > 0)
        {
            if (EVP_DigestUpdate(&md_context, buf, n) == 0)
            {
                snprintf(rp->errbuf, ERRBUF_SIZE,
                        "EVP_DigestUpdate() failed\n");
                goto bad;
            }
        }
        /* retrieve the digest value and length from the md context */
        if (EVP_DigestFinal(&md_context, digest, digest_len) == 0)
        {
            snprintf(rp->errbuf, ERRBUF_SIZE,
                    "EVP_DigestFinal() failed\n");
            goto bad;
        }
    }
    else
    {
        /*
         *  Digest a user's passphrase.  Since we know this no more
         *  than KEY_LENGTH bytes, we can do it all in one chunk.
         */
        if (EVP_DigestUpdate(&md_context, rp->passphrase,
                strlen(rp->passphrase)) == 0)
        {
            snprintf(rp->errbuf, ERRBUF_SIZE,
                    "EVP_DigestUpdate() failed\n");
            goto bad;
        }
        if (EVP_DigestFinal(&md_context, digest, digest_len) == 0)
        {
            snprintf(rp->errbuf, ERRBUF_SIZE,
                    "EVP_DigestFinal() failed\n");
            goto bad;
        }
    }

    return (digest);
bad:
    *digest_len = 0;
    return (NULL);
}


int
roil_cipher(struct roil_pack *rp)
{
    int n, m, mode;
    EVP_CIPHER_CTX ea_context;
    const EVP_CIPHER *ea;
    u_long bytecnt;
    u_char buf[BUF_SIZE], ebuf[BUF_SIZE], key[KEY_LENGTH], iv[IV_LENGTH];

    /* set the mode for the cipher functions */
    mode = (rp->flags & ENCRYPT) ? 1 : 0;

    /* add all available encryption algorithms to the hash table */
    OpenSSL_add_all_ciphers();

    if (rp->flags & ENCRYPT)
    {
        /*
         *  If we're encrypting, we have to first load and verify the 
         *  cipher specified at the command line.
         */
        ea = EVP_get_cipherbyname(rp->ea);
        if (ea == NULL)
        {
            snprintf(rp->errbuf, ERRBUF_SIZE, "unknown cipher %s\n",
                    rp->ea);
            return (-1);
        }
    }
    else    /* decrypting */
    {
        /*
         *  If we're decrypting, we have to check to see if this file was 
         *  previously encrypted by roil.  To do that, we read the first 8 
         *  bytes and see if they correspond to the "magic number" that is
         *  written to every roiled file prior to encryption.
         */
        n = read(rp->fd_in, buf, 8);
        if (n != 8)
        {   
            snprintf(rp->errbuf, ERRBUF_SIZE, "read error %s\n",
                    strerror(errno));
            return (-1);
        }
        if (bcmp(buf, magic, 8))
        {   
            snprintf(rp->errbuf, ERRBUF_SIZE, "%s is not a roiled file\n",
                    rp->fn_in);
            return (-1);
        }

        /*
         *  Next, we have to determine which symmetric cipher was used
         *  to encrypt the file.  That is written in the next 16 bytes
         *  of the file.
         */
        n = read(rp->fd_in, buf, 16);
        if (n != 16)
        {   
            snprintf(rp->errbuf, ERRBUF_SIZE, "read error %s\n",
                    strerror(errno));
            return (-1);
        }

        /*
         *  Look up the cipher by canonical name and if it's "good" fill
         *  in an EVP_CIPHER structure.
         */
        ea = EVP_get_cipherbyname(buf);
        if (ea == NULL)
        {
            snprintf(rp->errbuf, ERRBUF_SIZE, "unknown cipher %s\n",
                    buf);
            return (-1);
        }

        /*
         *  The next 8 bytes contain the initialization vector, which
         *  may or may not be used by the algorithm.  We store it either
         *  way.
         */
        n = read(rp->fd_in, iv, 8);
        if (n != 8)
        {
            snprintf(rp->errbuf, ERRBUF_SIZE, "read error %s\n",
                    strerror(errno));
            return (-1);
        }
    }

    /*
     *  Get a passphrase from the user to use as a key for the symmetric 
     *  encryption.
     */
    if (get_passphrase(rp->passphrase) == -1)
    {
        snprintf(rp->errbuf, ERRBUF_SIZE, "can't read passphrase %s\n",
                strerror(errno));
        return (-1);
    }

    /*
     *  Take the passphrase and hash it using SHA1 to create our
     *  symmetric key.
     */
    if (make_key(rp, key)  == -1)
    {
        /* error set in roil_digest() */
        return (-1);
    }

    /* we appear good to go; we open our output file */
    if (open_outputfile(rp) == -1)
    {
        /* error set in open_outputfile() */
        return (-1);
    }

    if (rp->flags & ENCRYPT)
    {
        /*
         *  Write out our 8 byte magic number to the file.  This will
         *  let the decryption code know if this file was encrypted by
         *  us or not.
         */
        n = write(rp->fd_out, magic, 8);
        if (n != 8)
        {
            snprintf(rp->errbuf, ERRBUF_SIZE, "write error %s\n",
                    strerror(errno));
            return (-1);
        }

        /*
         *  Write the encryption algorithm to the file, which will be
         *  NULL padded to 16 bytes.  This will allow the decryption
         *  code to figure it out without needing the user to specify.
         */
        memset(buf, 0, sizeof (buf));
        memcpy(buf,  rp->ea, strlen(rp->ea));
        n = write(rp->fd_out, buf, 16);
        if (n != 16)
        {
            snprintf(rp->errbuf, ERRBUF_SIZE, "write error %s\n",
                    strerror(errno));
            return (-1);
        }

        /*
         *  Some encryption algorithms use an initialization vector to
         *  seed the first round of encryption with (it acts as a dummy
         *  block).  We might need it so we'll get one and write it to
         *  the file next.
         */
        get_iv(iv);
        n = write(rp->fd_out, iv, 8);
        if (n != 8)
        {
            snprintf(rp->errbuf, ERRBUF_SIZE, "write error %s\n",
                    strerror(errno));
            return (-1);
        }
    }

    /*
     *  Initialize the cipher context.  Really all this does is zero
     *  out the structure.
     */
    EVP_CIPHER_CTX_init(&ea_context);

    /* initialize the encryption/decryption operation */
    if (EVP_CipherInit_ex(&ea_context, ea, NULL, key, iv, mode) == 0)
    {
        snprintf(rp->errbuf, ERRBUF_SIZE, "EVP_CipherInit_ex() failed\n");
        return (-1);
    }

    /*
     *  Encrypt/decrypt the file.  Read a block of data, encrypt it and 
     *  write it out to the file.
     */
    if (rp->flags & ENCRYPT)
    {
        fprintf(stderr, "\nencrypting file \"%s\"\n", rp->fn_in);
    }
    else
    {
        fprintf(stderr, "\ndecrypting %s encrypted file \"%s\"\n", buf,
                rp->fn_in);
    }
    bytecnt = 0;
    while ((n = read(rp->fd_in, buf, sizeof (buf))) > 0)
    {
        bytecnt += n;
        /*
         *  Encrypt or decrypt n bytes from buf and write the output to
         *  ebuf.
         */
        if (EVP_CipherUpdate(&ea_context, ebuf, &m, buf, n) == 0)
        {
            snprintf(rp->errbuf, ERRBUF_SIZE,
                    "EVP_CipherUpdate() failed\n");
            return (-1);
        }
        n = write(rp->fd_out, ebuf, m);
        if (n != m)
        {
            snprintf(rp->errbuf, ERRBUF_SIZE, "write error %s\n",
                    strerror(errno));
            return (-1);
        }
        fprintf(stderr, "byte: 0x%08lx\r", bytecnt);
    }
    /*
     *  Finalize the encryption or decryption by taking care of padding 
     *  the last block if necessary.
     */
    if (EVP_CipherFinal_ex(&ea_context, ebuf, &m) == 0)
    {
        snprintf(rp->errbuf, ERRBUF_SIZE,
                "EVP_CipherFinal_ex() failed\n");
        return (-1);
    }
    n = write(rp->fd_out, ebuf, m);
    if (n != m)
    {
        snprintf(rp->errbuf, ERRBUF_SIZE, "write error %s\n",
                strerror(errno));
        return (-1);
    }
    printf("\ndone, output file is \"%s\"\n", rp->fn_out);

    return (1);
}


int
get_passphrase(char *passphrase)
{
    int n, retry;
    char passphrase_match[KEY_LENGTH];
    struct termios term;

    /* we want to turn off terminal echoing so no one can see! */
    n = tcgetattr(STDIN_FILENO, &term);
    if (n == -1)
    {
        fprintf(stderr, "warning: password will be echoed\n");
        /* nonfatal */
    }
    else
    {
        /* disable terminal echo */
        term.c_lflag &= ~ECHO;
    }
    /* set our changed state "NOW" */
    n = tcsetattr(STDIN_FILENO, TCSANOW, &term);
    if (n == -1)
    {
        fprintf(stderr, "warning: password will be echoed\n");
        /* nonfatal */
    }

    retry = RETRY_THRESHOLD;
    memset(passphrase, 0, KEY_LENGTH);

again:

    printf("Passphrase: ");
    if (fgets(passphrase, KEY_LENGTH, stdin) == NULL)
    {
        return (-1);
    }
    passphrase[strlen(passphrase) - 1] = 0;

    printf("\nAgain: ");
    if (fgets(passphrase_match, KEY_LENGTH, stdin) == NULL)
    {
        return (-1);
    }
    passphrase_match[strlen(passphrase_match) - 1] = 0;

    /*
     *  Check to make sure they match.  It's safe to use strcmp here
     *  since we're confident both strings will be KEY_LENGTH or fewer 
     *  bytes.
     */
    if (strcmp(passphrase, passphrase_match))
    {
        if (retry <= 0)
        {
            /* we've run through this RETRY_THRESHOLD times, we're done */
            fprintf(stderr, "\nyou're hopeless; get typing lessons\n");
            errno = EPERM;  /* this is as good as any I suppose */
            return (-1);
        }
        fprintf(stderr, "\nno doofus, they don't match, try again\n");
        retry--;
        goto again;
    }
    memset(passphrase_match, 0, KEY_LENGTH);
    return (1);
}


int
make_key(struct roil_pack *rp, u_char *key)
{
    int len;
    u_char *p;

    strncpy(rp->md, "sha1", 4);

    p = roil_digest(rp, &len);
    if (p == NULL)
    {
        /* error set in roil_digest() */
        return (-1);
    }

    memcpy(key, p, len);
    return (1);
}


void
get_iv(u_char *iv)
{
    int n;

    /* XXX - should use the rand() interface from OpenSSL */
    srandom((unsigned)time(NULL));

    /* get 8 bytes of pseudo random value, from 0 - 255 */
    for (n = 0; n < IV_LENGTH; n++)
    {
        iv[n] = random() % 0xff;
    }
}


void
usage(char *name)
{
    printf("usage %s [options] file\n"
                    "-e cipher_type\t\tencrypt\n"
                    "-d\t\t\tdecrypt\n"
                    "-h\t\t\tthis blurb you see right here\n"
                    "-m message_digest\tmessage digest\n", name);
}


/* EOF */
