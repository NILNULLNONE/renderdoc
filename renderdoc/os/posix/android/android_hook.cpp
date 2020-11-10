/******************************************************************************
 * The MIT License (MIT)
 *
 * Copyright (c) 2019-2020 Baldur Karlsson
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 ******************************************************************************/

#include "common/common.h"
#include "common/threading.h"
#include "hooks/hooks.h"
#include "plthook/plthook.h"
#include "android/android.h"
#include "android/android_utils.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h> 
#include <stdio.h> 
#include <android/dlext.h>
#include <dlfcn.h>
#include <errno.h>
#include <jni.h>
#include <link.h>
#include <stddef.h>
#include <sys/mman.h>
#include <unistd.h>
#include <algorithm>
#include <map>
#include <set>

// uncomment the following to print (very verbose) debugging prints for the android PLT hooking
//#define HOOK_DEBUG_PRINT(...) RDCLOG(__VA_ARGS__)

#if !defined(HOOK_DEBUG_PRINT)
#define HOOK_DEBUG_PRINT(...) \
  do                          \
  {                           \
  } while(0)
#endif

// from plthook_elf.c
#if defined __x86_64__ || defined __x86_64
#define R_JUMP_SLOT R_X86_64_JUMP_SLOT
#define Elf_Rel ElfW(Rela)
#define ELF_R_TYPE ELF64_R_TYPE
#define ELF_R_SYM ELF64_R_SYM
#elif defined __i386__ || defined __i386
#define R_JUMP_SLOT R_386_JMP_SLOT
#define Elf_Rel ElfW(Rel)
#define ELF_R_TYPE ELF32_R_TYPE
#define ELF_R_SYM ELF32_R_SYM
#elif defined __arm__ || defined __arm
#define R_JUMP_SLOT R_ARM_JUMP_SLOT
#define Elf_Rel ElfW(Rel)
#define ELF_R_TYPE ELF32_R_TYPE
#define ELF_R_SYM ELF32_R_SYM
#elif defined __aarch64__ || defined __aarch64 /* ARM64 */
#define R_JUMP_SLOT R_AARCH64_JUMP_SLOT
#define Elf_Rel ElfW(Rela)
#define ELF_R_TYPE ELF64_R_TYPE
#define ELF_R_SYM ELF64_R_SYM
#else
#error unsupported OS
#endif

class HookingInfo
{
public:
  void AddFunctionHook(const FunctionHook &hook)
  {
    SCOPED_LOCK(lock);
    funchooks.push_back(hook);

    // add to map to speed-up lookup in GetFunctionHook
    funchook_map[hook.function] = hook;
  }

  void AddLibHook(const rdcstr &name)
  {
    SCOPED_LOCK(lock);
    if(!libhooks.contains(name))
      libhooks.push_back(name);
  }

  void AddHookCallback(const rdcstr &name, FunctionLoadCallback callback)
  {
    SCOPED_LOCK(lock);
    hookcallbacks[name].push_back(callback);
  }

  rdcarray<FunctionHook> GetFunctionHooks()
  {
    SCOPED_LOCK(lock);
    return funchooks;
  }

  void ClearHooks()
  {
    SCOPED_LOCK(lock);
    libhooks.clear();
    funchooks.clear();
    funchook_map.clear();
  }

  rdcarray<rdcstr> GetLibHooks()
  {
    SCOPED_LOCK(lock);
    return libhooks;
  }

  std::map<rdcstr, rdcarray<FunctionLoadCallback>> GetHookCallbacks()
  {
    SCOPED_LOCK(lock);
    return hookcallbacks;
  }

  FunctionHook GetFunctionHook(const rdcstr &name)
  {
    SCOPED_LOCK(lock);
    return funchook_map[name];
  }

  bool IsLibHook(const rdcstr &path)
  {
    SCOPED_LOCK(lock);
    for(const rdcstr &filename : libhooks)
    {
      if(path.contains(filename))
      {
        HOOK_DEBUG_PRINT("Intercepting and returning ourselves for %s (matches %s)", path.c_str(),
                         filename.c_str());
        return true;
      }
    }

    return false;
  }

  bool IsLibHook(void *handle)
  {
    SCOPED_LOCK(lock);
    for(const rdcstr &lib : libhooks)
    {
      void *libHandle = dlopen(lib.c_str(), RTLD_NOLOAD);
      HOOK_DEBUG_PRINT("%s is %p", lib.c_str(), libHandle);
      if(libHandle == handle)
        return true;
    }

    return false;
  }

  bool IsHooked(void *handle)
  {
    SCOPED_LOCK(lock);
    bool ret = hooked_handle_already.find(handle) != hooked_handle_already.end();
    return ret;
  }

  bool IsHooked(const rdcstr &soname)
  {
    SCOPED_LOCK(lock);
    if(hooked_soname_already.find(soname) != hooked_soname_already.end())
      return true;

    // above will be absolute path, allow substring matches
    for(const rdcstr &fn : hooked_soname_already)
      if(soname.contains(fn))
        return true;

    return false;
  }

  void SetHooked(void *handle)
  {
    SCOPED_LOCK(lock);
    hooked_handle_already.insert(handle);
  }

  void SetHooked(const rdcstr &soname)
  {
    SCOPED_LOCK(lock);
    hooked_soname_already.insert(soname);
  }

private:
  std::set<rdcstr> hooked_soname_already;
  std::set<void *> hooked_handle_already;

  rdcarray<FunctionHook> funchooks;
  std::map<rdcstr, FunctionHook> funchook_map;
  rdcarray<rdcstr> libhooks;

  std::map<rdcstr, rdcarray<FunctionLoadCallback>> hookcallbacks;

  Threading::CriticalSection lock;
};

HookingInfo &GetHookInfo()
{
  static HookingInfo hookinfo;
  return hookinfo;
}

void *intercept_dlopen(const char *filename, int flag)
{
  if(filename)
  {
    // if this is a library we're hooking, or a request for our own library in any form, return our
    // own library.
    // We need to intercept requests for our own library, because the android loader makes the
    // completely ridiculous decision to load multiple copies of the same library into a process if
    // it's dlopen'd with different paths. This obviously breaks with our hook install.
    if(strstr(filename, RENDERDOC_ANDROID_LIBRARY) || GetHookInfo().IsLibHook(rdcstr(filename)))
    {
      HOOK_DEBUG_PRINT("Intercepting dlopen for %s", filename);
      return dlopen(RENDERDOC_ANDROID_LIBRARY, flag);
    }
  }

  return NULL;
}

// we need this on both paths since interceptor-lib is unable to hook dlopen in libvulkan.so
static int dl_iterate_callback(struct dl_phdr_info *info, size_t size, void *data)
{
  if(info->dlpi_name == NULL)
  {
    HOOK_DEBUG_PRINT("Skipping NULL entry!");
    return 0;
  }
  rdcstr soname = info->dlpi_name;

  if(GetHookInfo().IsHooked(soname))
    return 0;

  HOOK_DEBUG_PRINT("Hooking %s", soname.c_str());
  GetHookInfo().SetHooked(soname);

  for(int ph = 0; ph < info->dlpi_phnum; ph++)
  {
    if(info->dlpi_phdr[ph].p_type != PT_DYNAMIC)
      continue;

    ElfW(Dyn) *dynamic = (ElfW(Dyn) *)(info->dlpi_addr + info->dlpi_phdr[ph].p_vaddr);

    ElfW(Sym) *dynsym = NULL;
    const char *strtab = NULL;
    size_t strtabcount = 0;
    Elf_Rel *pltbase = NULL;
    ElfW(Sword) pltcount = 0;

    while(dynamic->d_tag != DT_NULL)
    {
      if(dynamic->d_tag == DT_SYMTAB)
        dynsym = (ElfW(Sym) *)(info->dlpi_addr + dynamic->d_un.d_ptr);
      else if(dynamic->d_tag == DT_STRTAB)
        strtab = (const char *)(info->dlpi_addr + dynamic->d_un.d_ptr);
      else if(dynamic->d_tag == DT_STRSZ)
        strtabcount = dynamic->d_un.d_val;
      else if(dynamic->d_tag == DT_JMPREL)
        pltbase = (Elf_Rel *)(info->dlpi_addr + dynamic->d_un.d_ptr);
      else if(dynamic->d_tag == DT_PLTRELSZ)
        pltcount = dynamic->d_un.d_val / sizeof(Elf_Rel);

      /*
      if(dynamic->d_tag == DT_NEEDED)
        HOOK_DEBUG_PRINT("NEEDED [%i, %s]", dynamic->d_un.d_val, strtab + dynamic->d_un.d_val);
        */

      dynamic++;
    }

    if(!dynsym || !strtab || !pltbase || pltcount == 0 || strtabcount == 0)
    {
      RDCWARN("Missing required section to hook %s", info->dlpi_name);
      continue;
    }

    void **relro_base = NULL;
    void **relro_end = NULL;
    bool relro_failed = false;

    FILE *f = FileIO::fopen(info->dlpi_name, "r");

    // read the file on disk to get the .relro section
    if(f)
    {
      ElfW(Ehdr) ehdr;
      size_t read = FileIO::fread(&ehdr, sizeof(ehdr), 1, f);

      if(read == 1 && ehdr.e_ident[0] == ELFMAG0 && ehdr.e_ident[1] == 'E' &&
         ehdr.e_ident[2] == 'L' && ehdr.e_ident[3] == 'F')
      {
        FileIO::fseek64(f, ehdr.e_phoff, SEEK_SET);
        for(ElfW(Half) idx = 0; idx < ehdr.e_phnum; idx++)
        {
          ElfW(Phdr) phdr;
          read = FileIO::fread(&phdr, sizeof(phdr), 1, f);
          if(read != 1)
          {
            RDCWARN("Failed reading section");
            break;
          }

          if(phdr.p_type == PT_GNU_RELRO)
          {
            relro_base = (void **)(info->dlpi_addr + phdr.p_vaddr);
            relro_end = (void **)(info->dlpi_addr + phdr.p_vaddr + phdr.p_memsz);
          }
        }
      }
      else
      {
        RDCWARN("Didn't get valid ELF header");
      }

      FileIO::fclose(f);
    }
    else
    {
      RDCWARN("Couldn't open '%s' to look for relro!", info->dlpi_name);
      relro_failed = true;
    }

    if(relro_base)
      HOOK_DEBUG_PRINT("Got relro %p -> %p", relro_base, relro_end);
    HOOK_DEBUG_PRINT("Got %i PLT entries", pltcount);

    int pagesize = sysconf(_SC_PAGE_SIZE);

    for(ElfW(Sword) i = 0; i < pltcount; i++)
    {
      Elf_Rel *plt = pltbase + i;
      if(ELF_R_TYPE(plt->r_info) != R_JUMP_SLOT)
      {
        HOOK_DEBUG_PRINT("[%i]: Mismatched type %i vs %i", i, ELF_R_TYPE(plt->r_info), R_JUMP_SLOT);
        continue;
      }

      size_t idx = ELF_R_SYM(plt->r_info);
      size_t name = dynsym[idx].st_name;
      if(name + 1 > strtabcount)
      {
        HOOK_DEBUG_PRINT("[%i] name out of boundstoo big section header string table index: %zu", i,
                         name);
        continue;
      }

      const char *importname = strtab + name;
      void **import = (void **)(info->dlpi_addr + plt->r_offset);

      HOOK_DEBUG_PRINT("[%i] %s at %p (ptr to %p)", i, importname, import, *import);

      const FunctionHook repl = GetHookInfo().GetFunctionHook(importname);
      if(repl.hook)
      {
        HOOK_DEBUG_PRINT("replacing %s!", importname);

        uintptr_t pagebase = 0;

        if(relro_failed || (relro_base <= import && import <= relro_end))
        {
          if(relro_failed)
            HOOK_DEBUG_PRINT("Couldn't get relro sections - mapping read/write");
          else
            HOOK_DEBUG_PRINT("In relro range - %p <= %p <= %p", relro_base, import, relro_end);
          pagebase = uintptr_t(import) & ~(pagesize - 1);

          int ret = mprotect((void *)pagebase, pagesize, PROT_READ | PROT_WRITE);
          if(ret != 0)
          {
            RDCERR("Couldn't read/write the page: %d %d", ret, errno);
            return 0;
          }

          HOOK_DEBUG_PRINT("Marked page read/write");
        }
        else
        {
          HOOK_DEBUG_PRINT("Not in relro! - %p vs %p vs %p", relro_base, import, relro_end);
        }

        // note we don't save the orig function here, since we want to apply our library priorities
        // and we don't know what order these headers will be iterated in. See EndHookRegistration
        // for where we iterate and fetch all the function pointers we want.
        *import = repl.hook;

        if(pagebase)
        {
          if(relro_failed)
          {
            HOOK_DEBUG_PRINT(
                "Couldn't find relro sections - being conservative and leaving read-write");
          }
          else
          {
            HOOK_DEBUG_PRINT("Moving back to read-only");
            mprotect((void *)pagebase, pagesize, PROT_READ);
          }
        }

        HOOK_DEBUG_PRINT("[%i*] %s at %p (ptr to %p)", i, importname, import, *import);
      }
    }
  }

  return 0;
}

// android has a special dlopen that passes the caller address in.
typedef void *(*pfn__loader_dlopen)(const char *filename, int flags, const void *caller_addr);

typedef void *(*pfnandroid_dlopen_ext)(const char *__filename, int __flags,
                                       const android_dlextinfo *__info);

pfnandroid_dlopen_ext real_android_dlopen_ext = NULL;

pfn__loader_dlopen loader_dlopen = NULL;
uint64_t suppressTLS = 0;

void process_dlopen(const char *filename, int flag)
{
  if(filename && !GetHookInfo().IsHooked(rdcstr(filename)))
  {
    HOOK_DEBUG_PRINT("iterating after %s", filename);
    dl_iterate_phdr(dl_iterate_callback, NULL);
    GetHookInfo().SetHooked(filename);
  }
  else
  {
    HOOK_DEBUG_PRINT("Ignoring");
  }
}

extern "C" __attribute__((visibility("default"))) void *hooked_dlopen(const char *filename, int flag)
{
	pid_t tid = gettid();
	RDCLOG("<%d> _____________________________________ dlopen %s, %d", tid, filename, flag);

  // get caller address immediately.
  const void *caller_addr = __builtin_return_address(0);

  HOOK_DEBUG_PRINT("hooked_dlopen for %s | %d", filename, flag);
  void *ret = intercept_dlopen(filename, flag);

  // if we intercepted, return immediately
  if(ret)
    return ret;

  ret = loader_dlopen(filename, flag, caller_addr);
  HOOK_DEBUG_PRINT("Got %p", ret);

  if(filename && ret)
    process_dlopen(filename, flag);

  return ret;
}


extern "C" __attribute__((visibility("default"))) void *hooked_android_dlopen_ext(
    const char *__filename, int __flags, const android_dlextinfo *__info)
{
  HOOK_DEBUG_PRINT("hooked_android_dlopen_ext for %s | %d", __filename, __flags);

  void *ret = intercept_dlopen(__filename, __flags);

  // if we intercepted, return immediately
  if(ret)
    return ret;

  // otherwise return the 'real' result.
  if(real_android_dlopen_ext == NULL)
    ret = real_android_dlopen_ext(__filename, __flags, __info);
  else
    ret = android_dlopen_ext(__filename, __flags, __info);
  HOOK_DEBUG_PRINT("Got %p", ret);

  if(__filename && ret)
    process_dlopen(__filename, __flags);

  return ret;
}

bool hooks_suppressed();

extern "C" __attribute__((visibility("default"))) void *hooked_dlsym(void *handle, const char *symbol)
{
	if(handle == NULL || symbol == NULL || hooks_suppressed())
    return dlsym(handle, symbol);

  const FunctionHook repl = GetHookInfo().GetFunctionHook(symbol);

  if(repl.hook == NULL)
    return dlsym(handle, symbol);

  if(!GetHookInfo().IsHooked(handle))
  {
    dl_iterate_phdr(dl_iterate_callback, NULL);
    GetHookInfo().SetHooked(handle);
  }

  HOOK_DEBUG_PRINT("Got dlsym for %s which we want in %p...", symbol, handle);

  if(GetHookInfo().IsLibHook(handle))
  {
    HOOK_DEBUG_PRINT("identified dlsym(%s) we want to interpose! returning %p", symbol, repl.hook);
    return repl.hook;
  }

  void *ret = dlsym(handle, symbol);
  Dl_info info = {};
  dladdr(ret, &info);
  HOOK_DEBUG_PRINT("real ret is %p in %s", ret, info.dli_fname);
  return ret;
}

extern "C" typedef int(*OpenType)(const char *path, int oflag);

extern "C" typedef FILE *(*FopenType)(const char *filename, const char *mode);

//extern "C" typedef size_t(*FreadType)(void * ptr, size_t size, size_t count, FILE * stream);

static FopenType orig_fopen;

static OpenType orig_open;

//static FreadType orig_fread;

static bool starts_with(const char *str, const char *target)
{
  int str_len = strlen(str);
  int target_len = strlen(target);
  if(str_len >= target_len)
  {
    for(int i = 0; i < target_len; i++)
    {
		if (str[i] != target[i])
		{
			return false;
		}
    }
	return true;
  }
  return false;
}

static bool ends_with(const char *str, const char *target) {
	int str_len = strlen(str);
	int target_len = strlen(target);
	if (str_len >= target_len)
	{
		for (int i = 1; i <= target_len; i++)
		{
			if (str[str_len - i] != target[target_len - i])
			{
				return false;
			}
		}
		return true;
	}
	return false;
}

// You must free the result if result is non-NULL.
char *str_replace(char *orig, const char *rep, const char *with) {
	char *result; // the return string
	char *ins;    // the next insert point
	char *tmp;    // varies
	int len_rep;  // length of rep (the string to remove)
	int len_with; // length of with (the string to replace rep with)
	int len_front; // distance between rep and end of last rep
	int count;    // number of replacements

	// sanity checks and initialization
	if (!orig || !rep)
		return NULL;
	len_rep = strlen(rep);
	if (len_rep == 0)
		return NULL; // empty rep causes infinite loop during count
	if (!with)
		return NULL;
	len_with = strlen(with);

	// count the number of replacements needed
	ins = orig;
	for (count = 0; (bool)(tmp = strstr(ins, rep)); ++count) {
		ins = tmp + len_rep;
	}

	tmp = result = (char*)malloc(strlen(orig) + (len_with - len_rep) * count + 1);

	if (!result)
		return NULL;

	// first time through the loop, all the variable are set correctly
	// from here on,
	//    tmp points to the end of the result string
	//    ins points to the next occurrence of rep in orig
	//    orig points to the remainder of orig after "end of rep"
	while (count--) {
		ins = strstr(orig, rep);
		len_front = ins - orig;
		tmp = strncpy(tmp, orig, len_front) + len_front;
		tmp = strcpy(tmp, with) + len_with;
		orig += len_front + len_rep; // move to next "end of rep"
	}
	strcpy(tmp, orig);
	return result;
}

static int counter = 0;
//static int status_counter = 0;
// /data/app/com.tencent.tmgp.wuxia-60OMJPRIwCqNGXQxHQtRbQ==/lib/arm64/libAkSoundEngine.so
// /data/app/com.miHoYo.Yuanshen-vMTbcjONkjD8rjYmJNt07g==/lib/arm64/libtersafe2.so
//const char* TheirName = "/data/app/com.tencent.tmgp.wuxia-60OMJPRIwCqNGXQxHQtRbQ==/lib/arm64/libAkSoundEngine.so";
const char* TheirName = "/data/app/com.miHoYo.Yuanshen-vMTbcjONkjD8rjYmJNt07g==/lib/arm64/libtersafe2.so";

static char* base_open_maps(const char* filename)
{
	//RDCLOG("!!!!!!!!!!!!!!!!!!!!!!!!! READ MAPS");
//RDCLOG("!!!!!!!!!!!!!!!!!!!!!!!!! counter: %d", counter);

// open true .maps
	FILE *TrueMapsFile = orig_fopen(filename, "r");
	//RDCLOG("!!!!!!!!!!!!!!!!!!!!!!!!! True Map File: %p", TrueMapsFile);
	// create fake file name
	//char FakeFilename[1024] = {};
	char* FakeFilename = (char*)malloc(sizeof(char) * 1024);
	(counter = (counter + 1) % 10);
	sprintf(FakeFilename, "%s_%d", "/data/local/tmp/f_a_k_e_m_a_p_s", counter);
	// open fake .maps
	FILE *FakeMapsFile = orig_fopen(FakeFilename, "w");
	//RDCLOG("!!!!!!!!!!!!!!!!!!!!!!!!! Fake Map File: %s %p", FakeFilename, FakeMapsFile);

	char LineBuf[1024] = {};
	char* OurSoPath = NULL;
	const char* PrefStr = "/data/app/com.cxxxr.dxxxr";
	while (fgets(LineBuf, 1024, TrueMapsFile)) {
		char* Prefix = strstr(LineBuf, PrefStr);
		if (Prefix)
		{
			if (!OurSoPath)
			{
				const int Len = sizeof(char) * 78;
				OurSoPath = (char*)malloc(Len + 1);
				memset(OurSoPath, 0, Len + 1);
				strncpy(OurSoPath, Prefix, Len);
			}
			auto Result = str_replace(LineBuf, OurSoPath, TheirName);
			fputs(Result, FakeMapsFile);
			//RDCLOG("%s, %s, %s", Result, OurSoPath, TheirName);
		}
		else
		{
			fputs(LineBuf, FakeMapsFile);
		}
	}

	fclose(TrueMapsFile);
	fclose(FakeMapsFile);
	return FakeFilename;
}

//static char* base_open_status(const char* filename)
//{
//	//RDCLOG("!!!!!!!!!!!!!!!!!!!!!!!!! READ MAPS");
////RDCLOG("!!!!!!!!!!!!!!!!!!!!!!!!! status_counter: %d", status_counter);
//
//// open true .maps
//	FILE *TrueMapsFile = orig_fopen(filename, "r");
//	//RDCLOG("!!!!!!!!!!!!!!!!!!!!!!!!! True Map File: %p", TrueMapsFile);
//	// create fake file name
//	//char FakeFilename[1024] = {};
//	char* FakeFilename = (char*)malloc(sizeof(char) * 1024);
//	(status_counter = (status_counter + 1) % 10);
//	sprintf(FakeFilename, "%s_%d", "/data/local/tmp/f_a_k_e_s_t_a_t_u_s", status_counter);
//	// open fake .maps
//	FILE *FakeMapsFile = orig_fopen(FakeFilename, "w");
//	//RDCLOG("!!!!!!!!!!!!!!!!!!!!!!!!! Fake Map File: %s %p", FakeFilename, FakeMapsFile);
//
//	char LineBuf[1024] = {};
//	char* OurSoPath = NULL;
//	while (fgets(LineBuf, 1024, TrueMapsFile)) {
//		if (starts_with(LineBuf, "TracerPid"))
//		{
//			sprintf(LineBuf, "TracerPid:\t0\n");
//			fputs(LineBuf, FakeMapsFile);
//			//RDCLOG("%s, %s, %s", Result, OurSoPath, TheirName);
//		}
//		else
//		{
//			fputs(LineBuf, FakeMapsFile);
//		}
//	}
//
//	fclose(TrueMapsFile);
//	fclose(FakeMapsFile);
//	return FakeFilename;
//}
//
//static FILE* fopen_status(const char* filename, const char* mode)
//{
//	char* fn = base_open_status(filename);
//	auto ret = orig_fopen(fn, mode);
//	free(fn);
//	return ret;
//}
//
//static int open_status(const char* path, int oflag)
//{	
//	auto fn = base_open_status(path);
//	auto ret = orig_open(fn, oflag);
//	free(fn);
//	return ret;
//}
//
static FILE* fopen_maps(const char* filename, const char* mode)
{
	auto fn = base_open_maps(filename);
	auto ret = orig_fopen(fn, mode);
	free(fn);
	return ret;
}

static int open_maps(const char* path, int oflag)
{
	auto fn = base_open_maps(path);
	auto ret = orig_open(fn, oflag);
	free(fn);
	return ret;
}

//static void log_callstack()
//{
//	return;
//}

// /data/app/com.miHoYo.Yuanshen-vMTbcjONkjD8rjYmJNt07g==/lib/arm64/libunity.so
// /data/app/com.cxxxr.dxxxr.a6r4m-pnDWnX65bDkYXln-U99fTQ==/lib/arm64/libdxxxv.so
extern "C" __attribute__((visibility("default"))) FILE *hooked_fopen(const char *filename, const char *mode)
{
  // if(filename && mode)
  //{
	pid_t tid = gettid();
	RDCLOG("<%d> ################################### fopen %s, %s", tid, filename, mode);
	//if ((starts_with("/proc/") && ends_with("/maps")) || starts_with("/data/app/com.cxxxr.dxxxr."))
	//{
	//	log_callstack();
	//}

   if (starts_with(filename, "/proc/") && ends_with(filename, "/maps"))
   {
	   return fopen_maps(filename, mode);
   }

   if (starts_with(filename, "/proc/") && ends_with(filename, "/status"))
   {
	   //return fopen_status(filename, mode);
	   //(void)fopen_status;
   }

   //if (starts_with(filename, "/data/app/com.cxxxr.dxxxr.")
	  // && ends_with(filename, ".apk"))
   //{
	  // const char* fake_apk_path = "/data/app/com.miHoYo.Yuanshen-vMTbcjONkjD8rjYmJNt07g==/base.apk";
	  // RDCLOG("*********************************** fake com.cxxxr.dxxr, %s", filename);
	  // return orig_fopen(fake_apk_path, mode);
   //}
  //if(starts_with(filename, "/proc/"))
  //{
	 // if (ends_with(filename, "/maps")) {
		//  const char *fake_maps_path = "/data/local/tmp/fake_ys.maps";
		//  FILE* fake_file = orig_fopen(fake_maps_path, mode);
		//  RDCLOG("################################### fake maps open %s %p", filename, fake_file);
		//  return fake_file;
	 // }
	 // else if(ends_with(filename, "/smaps")){
		//  const char *fake_smaps_path = "/data/local/tmp/fake_ys.smaps";
		//  FILE* fake_file = orig_fopen(fake_smaps_path, mode);
		//  RDCLOG("################################### fake smaps open %s %p", filename, fake_file);
		//  return fake_file;
	 // }
  //}
	 // 
  //RDCLOG("################################### normal open %s %s", filename, mode);
  return orig_fopen(filename, mode);
}

extern "C" __attribute__((visibility("default"))) int hooked_open(const char *path, int oflag)
{
	pid_t tid = gettid();
	RDCLOG("<%d> ************************************************ open %s, %d", tid, path, oflag);
	//if ((starts_with("/proc/") && ends_with("/maps")) || starts_with("/data/app/com.cxxxr.dxxxr."))
	//{
	//	log_callstack();
	//}

	if (starts_with(path, "/proc/") && ends_with(path, "/maps"))
	{
		return open_maps(path, oflag);
	}

	if (starts_with(path, "/proc/") && ends_with(path, "/status"))
	{
		//return open_status(path, oflag);
		//(void)open_status;
	}
	return orig_open(path, oflag);
}

//extern "C" __attribute__((visibility("default"))) size_t fread(void * ptr, size_t size, size_t count, FILE * stream)
//{
//	return orig_fread(ptr, size, count, stream);
//}

static void InstallHooksCommon()
{
  suppressTLS = Threading::AllocateTLSSlot();

  // blacklist hooking certain system libraries or ourselves
  GetHookInfo().SetHooked(RENDERDOC_ANDROID_LIBRARY);
  GetHookInfo().SetHooked("libc.so");
  GetHookInfo().SetHooked("libvndksupport.so");

  real_android_dlopen_ext = &android_dlopen_ext;

  loader_dlopen = (pfn__loader_dlopen)dlsym(RTLD_NEXT, "__loader_dlopen");

  if(loader_dlopen)
  {
    LibraryHooks::RegisterFunctionHook("", FunctionHook("dlopen", NULL, (void *)&hooked_dlopen));
  }
  else
  {
    RDCWARN("Couldn't find __loader_dlopen, falling back to slow path for dlopen hooking");
    LibraryHooks::RegisterFunctionHook("", FunctionHook("dlsym", NULL, (void *)&hooked_dlsym));
  }
  LibraryHooks::RegisterFunctionHook(
      "", FunctionHook("fopen", (void **)&orig_fopen, (void *)&hooked_fopen));
  LibraryHooks::RegisterFunctionHook(
	  "", FunctionHook("open", (void **)&orig_open, (void *)&hooked_open));
  LibraryHooks::RegisterFunctionHook(
      "", FunctionHook("android_dlopen_ext", NULL, (void *)&hooked_android_dlopen_ext));
}

#if defined(RENDERDOC_HAVE_INTERCEPTOR_LIB)

void intercept_error(void *, const char *error_msg)
{
  RDCERR("intercept_error: %s", error_msg);
}

#include "interceptor-lib/include/interceptor.h"

void PatchHookedFunctions()
{
  RDCLOG("Applying hooks with interceptor-lib");

// see below - Huawei workaround
#if defined(__LP64__)
  LibraryHooks::RegisterLibraryHook("/system/lib64/libhwgl.so", NULL);
#else
  LibraryHooks::RegisterLibraryHook("/system/lib/libhwgl.so", NULL);
#endif

  rdcarray<rdcstr> libs = GetHookInfo().GetLibHooks();
  rdcarray<FunctionHook> funchooks = GetHookInfo().GetFunctionHooks();

  // we just leak this
  void *intercept = InitializeInterceptor();

  std::set<rdcstr> fallbacklibs;
  std::set<FunctionHook> fallbackhooks;

  for(const rdcstr &lib : libs)
  {
    void *handle = dlopen(lib.c_str(), RTLD_NOW);

    bool huawei = lib.contains("libhwgl.so");

    if(!handle)
    {
      HOOK_DEBUG_PRINT("Didn't get handle for %s", lib.c_str());
      continue;
    }

    HOOK_DEBUG_PRINT("Hooking %s = %p", lib.c_str(), handle);

    std::set<void *> foundfunctions;

    for(const FunctionHook &hook : funchooks)
    {
      void *oldfunc = dlsym(handle, hook.function.c_str());

      // UNTESTED workaround taken directly from GAPID, in installer.cpp. Quoted comment:
      /*
            // Huawei implements all functions in this library with prefix,
            // all GL functions in libGLES*.so are just trampolines to his.
            // However, we do not support trampoline interception for now,
            // so try to intercept the internal implementation instead.
      */
      if(huawei && oldfunc == NULL)
        oldfunc = dlsym(handle, ("hw_" + hook.function).c_str());

      if(GetHookInfo().IsHooked(oldfunc))
        continue;

      if(!oldfunc)
      {
        HOOK_DEBUG_PRINT("%s didn't have %s", lib.c_str(), hook.function.c_str());
        continue;
      }

      HOOK_DEBUG_PRINT("Hooking %s::%s = %p with %p", lib.c_str(), hook.function.c_str(), oldfunc,
                       hook.hook);

      void *trampoline = NULL;

      bool success = InterceptFunction(intercept, oldfunc, hook.hook, &trampoline, &intercept_error);

      if(!hook.orig)
        RDCWARN("No original pointer for hook of '%s' - trampoline will be lost!",
                hook.function.c_str());

      if(hook.orig && *hook.orig == NULL)
        *hook.orig = trampoline;

      if(success)
      {
        HOOK_DEBUG_PRINT("Hooked successfully, trampoline is %p", trampoline);
      }
      else
      {
        RDCERR("Failed to hook %s::%s!", lib.c_str(), hook.function.c_str());
        fallbacklibs.insert(lib);
        fallbackhooks.insert(hook);
      }

      GetHookInfo().SetHooked(oldfunc);
    }
  }

  // we still need to hook android_dlopen_ext with interceptor-lib so that we can intercept the
  // vulkan loader's attempts to load our library and prevent it from loading a second copy (!!)
  // into the process.
  // Unfortunately, interceptor-lib can't hook this function so we need to set up the PLT hooking.
  // This is just a minimal setup to intercept that one function.
  GetHookInfo().ClearHooks();

  for(const rdcstr &l : fallbacklibs)
  {
    RDCLOG("Falling back to PLT hooking for %s", l.c_str());
    GetHookInfo().AddLibHook(l);
  }

  for(const FunctionHook &hook : fallbackhooks)
  {
    RDCLOG("Falling back to PLT hooking for %s", hook.function.c_str());
    GetHookInfo().AddFunctionHook(hook);
  }
}

#else

void PatchHookedFunctions()
{
  RDCLOG("Applying hooks with PLT hooks");
}

#endif

bool LibraryHooks::Detect(const char *identifier)
{
  return dlsym(RTLD_DEFAULT, identifier) != NULL;
}

void LibraryHooks::RemoveHooks()
{
  RDCERR("Removing hooks is not possible on this platform");
}

void LibraryHooks::BeginHookRegistration()
{
  // nothing to do
}

void LibraryHooks::RegisterFunctionHook(const char *libraryName, const FunctionHook &hook)
{
  // we don't use the library name on android
  (void)libraryName;
  HOOK_DEBUG_PRINT("Registering function hook for %s: %p", hook.function.c_str(), hook.hook);
  GetHookInfo().AddFunctionHook(hook);
}

void LibraryHooks::RegisterLibraryHook(const char *name, FunctionLoadCallback cb)
{
  GetHookInfo().AddLibHook(name);

  HOOK_DEBUG_PRINT("Registering library hook for %s %s", name, cb ? "with callback" : "");

  // open the library immediately if we can
  dlopen(name, RTLD_NOW);

  if(cb)
    GetHookInfo().AddHookCallback(name, cb);
}

void LibraryHooks::IgnoreLibrary(const char *libraryName) {}

void LibraryHooks::EndHookRegistration()
{
  HOOK_DEBUG_PRINT("EndHookRegistration");

  // ensure we load all libraries we can immediately, so they are immediately hooked and don't get
  // loaded later.
  rdcarray<rdcstr> libs = GetHookInfo().GetLibHooks();
  for(const rdcstr &lib : libs)
  {
    void *handle = dlopen(lib.c_str(), RTLD_GLOBAL);
    HOOK_DEBUG_PRINT("%s: %p", lib.c_str(), handle);
  }

  // try to prevent the library from being unloaded, increment our dlopen refcount (might not work
  // on android, but we'll try!)
  // we use RTLD_NOLOAD to prevent a second copy being loaded if this path doesn't refer to
  // ourselves or otherwise breaks because of android's terrible library handling.
  {
    rdcstr selfLib;
    FileIO::GetLibraryFilename(selfLib);
    if(FileIO::exists(selfLib.c_str()))
    {
      void *handle = dlopen(selfLib.c_str(), RTLD_NOW | RTLD_NOLOAD | RTLD_LOCAL);
      if(handle)
        RDCLOG("Dummy-loaded %s with dlopen to prevent library unload", selfLib.c_str());
      else
        RDCLOG("Failed to dummy-loaded %s with dlopen", selfLib.c_str());
    }
    else
    {
      RDCLOG("Couldn't dummy-load %s because it doesn't exist", selfLib.c_str());
    }
  }

  if(libs.empty())
  {
    RDCLOG("No library hooks registered, not doing any hooking");
    return;
  }

  PatchHookedFunctions();

  // this already hooks dlopen (if possible) and android_dlopen_ext, which is enough
  InstallHooksCommon();

  LibraryHooks::Refresh();

  // iterate our list of libraries and look up the original pointer for any that we don't already
  // have. If we have interceptor-lib this will only be for functions that failed to generate a
  // trampoline and we're PLT hooking - without interceptor-lib this will be all functions, but it
  // will allow us to control the order/priority.
  rdcarray<rdcstr> libraryHooks = GetHookInfo().GetLibHooks();
  rdcarray<FunctionHook> functionHooks = GetHookInfo().GetFunctionHooks();

  RDCLOG("Fetching %zu original function pointers over %zu libraries", functionHooks.size(),
         libraryHooks.size());

  for(auto it = libraryHooks.begin(); it != libraryHooks.end(); ++it)
  {
    void *handle = dlopen(it->c_str(), RTLD_NOLOAD | RTLD_GLOBAL);

    if(handle)
    {
      for(FunctionHook &hook : functionHooks)
      {
        if(hook.orig && *hook.orig == NULL)
          *hook.orig = dlsym(handle, hook.function.c_str());
      }
    }
  }

  RDCLOG("Finished");

  // call the callbacks for any libraries that loaded now. If the library wasn't loaded above then
  // it can't be loaded, since we only hook system libraries.
  std::map<rdcstr, rdcarray<FunctionLoadCallback>> callbacks = GetHookInfo().GetHookCallbacks();
  for(const std::pair<rdcstr, rdcarray<FunctionLoadCallback>> &cb : callbacks)
  {
    void *handle = dlopen(cb.first.c_str(), RTLD_GLOBAL);
    if(handle)
    {
      HOOK_DEBUG_PRINT("Calling callbacks for %s", cb.first.c_str());
      for(FunctionLoadCallback callback : cb.second)
        if(callback)
          callback(handle);
    }
  }

  RDCLOG("Called library callbacks - hook registration complete");
}

void LibraryHooks::Refresh()
{
  if(suppressTLS == 0)
  {
    RDCLOG("Not refreshing android hooks with no libraries registered");
    return;
  }

  RDCLOG("Refreshing android hooks...");
  dl_iterate_phdr(dl_iterate_callback, NULL);
  RDCLOG("Refreshed");
}

ScopedSuppressHooking::ScopedSuppressHooking()
{
  if(suppressTLS == 0)
    return;

  uintptr_t old = (uintptr_t)Threading::GetTLSValue(suppressTLS);
  Threading::SetTLSValue(suppressTLS, (void *)(old + 1));
}

ScopedSuppressHooking::~ScopedSuppressHooking()
{
  if(suppressTLS == 0)
    return;

  uintptr_t old = (uintptr_t)Threading::GetTLSValue(suppressTLS);
  Threading::SetTLSValue(suppressTLS, (void *)(old - 1));
}

bool hooks_suppressed()
{
  if(suppressTLS == 0)
    return true;

  return (uintptr_t)Threading::GetTLSValue(suppressTLS) > 0;
}
