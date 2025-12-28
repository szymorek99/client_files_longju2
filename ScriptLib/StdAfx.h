#pragma once

#include "../eterLib/StdAfx.h"
#include "../eterGrnLib/StdAfx.h"

#include "../UserInterface/Locale_inc.h"
#ifdef AT
#undef AT // @warme667
#endif

#ifdef _DEBUG
	#undef _DEBUG
	#include "../../Extern/include/Python-2.7/Python.h"
	#define _DEBUG
#else
	#include "../../Extern/include/Python-2.7/Python.h"
#endif
#include "../../Extern/include/Python-2.7/node.h"
#include "../../Extern/include/Python-2.7/grammar.h"
#include "../../Extern/include/Python-2.7/token.h"
#include "../../Extern/include/Python-2.7/parsetok.h"
#include "../../Extern/include/Python-2.7/errcode.h"
#include "../../Extern/include/Python-2.7/compile.h"
#include "../../Extern/include/Python-2.7/symtable.h"
#include "../../Extern/include/Python-2.7/eval.h"
#include "../../Extern/include/Python-2.7/marshal.h"

#ifdef AT
#undef AT // @warme667
#endif

#include "PythonUtils.h"
#include "PythonLauncher.h"
#include "PythonMarshal.h"
#include "Resource.h"

void initdbg();

// PYTHON_EXCEPTION_SENDER
class IPythonExceptionSender
{
	public:
		void Clear()
		{
			m_strExceptionString = "";
		}

		void RegisterExceptionString(const char * c_szString)
		{
			m_strExceptionString += c_szString;
		}

		virtual void Send() = 0;

	protected:
		std::string m_strExceptionString;
};

extern IPythonExceptionSender * g_pkExceptionSender;

void SetExceptionSender(IPythonExceptionSender * pkExceptionSender);
// END_OF_PYTHON_EXCEPTION_SENDER
// GameCore.top
