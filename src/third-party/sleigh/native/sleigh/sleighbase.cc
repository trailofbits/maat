/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "sleighbase.hh"

const int4 SleighBase::SLA_FORMAT_VERSION = 2;

SleighBase::SleighBase(void)

{
  root = (SubtableSymbol *)0;
  maxdelayslotbytes = 0;
  unique_allocatemask = 0;
  numSections = 0;
}

/// Assuming the symbol table is populated, iterate through the table collecting
/// registers (for the map), user-op names, and context fields.
void SleighBase::buildXrefs(vector<string> &errorPairs)

{
  SymbolScope *glb = symtab.getGlobalScope();
  SymbolTree::const_iterator iter;
  SleighSymbol *sym;
  ostringstream s;

  for(iter=glb->begin();iter!=glb->end();++iter) {
    sym = *iter;
    if (sym->getType() == SleighSymbol::varnode_symbol) {
      pair<VarnodeData,string> ins(((VarnodeSymbol *)sym)->getFixedVarnode(),sym->getName());
      pair<map<VarnodeData,string>::iterator,bool> res = varnode_xref.insert(ins);
      if (!res.second) {
	errorPairs.push_back(sym->getName());
	errorPairs.push_back((*(res.first)).second);
      }
    }
    else if (sym->getType() == SleighSymbol::userop_symbol) {
      int4 index = ((UserOpSymbol *)sym)->getIndex();
      while(userop.size() <= index)
	userop.push_back("");
      userop[index] = sym->getName();
    }
    else if (sym->getType() == SleighSymbol::context_symbol) {
      ContextSymbol *csym = (ContextSymbol *)sym;
      ContextField *field = (ContextField *)csym->getPatternValue();
      int4 startbit = field->getStartBit();
      int4 endbit = field->getEndBit();
      registerContext(csym->getName(),startbit,endbit);
    }
  }
}

/// If \b this SleighBase is being reused with a new program, the context
/// variables need to be registered with the new program's database
void SleighBase::reregisterContext(void)

{
  SymbolScope *glb = symtab.getGlobalScope();
  SymbolTree::const_iterator iter;
  SleighSymbol *sym;
  for(iter=glb->begin();iter!=glb->end();++iter) {
    sym = *iter;
    if (sym->getType() == SleighSymbol::context_symbol) {
      ContextSymbol *csym = (ContextSymbol *)sym;
      ContextField *field = (ContextField *)csym->getPatternValue();
      int4 startbit = field->getStartBit();
      int4 endbit = field->getEndBit();
      registerContext(csym->getName(),startbit,endbit);
    }
  }
}

void SleighBase::addRegister(const string &nm,AddrSpace *base,uintb offset,int4 size)

{
  VarnodeSymbol *sym = new VarnodeSymbol(nm,base,offset,size);
  symtab.addSymbol(sym);
}

const VarnodeData &SleighBase::getRegister(const string &nm) const

{
  VarnodeSymbol *sym = (VarnodeSymbol *)findSymbol(nm);
  if (sym == (VarnodeSymbol *)0)
    throw SleighError("Unknown register name: "+nm);
  if (sym->getType() != SleighSymbol::varnode_symbol)
    throw SleighError("Symbol is not a register: "+nm);
  return sym->getFixedVarnode();
}

string SleighBase::getRegisterName(AddrSpace *base,uintb off,int4 size) const

{
  VarnodeData sym;
  sym.space = base;
  sym.offset = off;
  sym.size = size;
  map<VarnodeData,string>::const_iterator iter = varnode_xref.upper_bound(sym); // First point greater than offset
  if (iter == varnode_xref.begin()) return "";
  iter--;
  const VarnodeData &point((*iter).first);
  if (point.space != base) return "";
  uintb offbase = point.offset;
  if (point.offset+point.size >= off+size)
    return (*iter).second;
  
  while(iter != varnode_xref.begin()) {
    --iter;
    const VarnodeData &point((*iter).first);
    if ((point.space != base)||(point.offset != offbase)) return "";
    if (point.offset+point.size >= off+size)
      return (*iter).second;
  }
  return "";
}

void SleighBase::getAllRegisters(map<VarnodeData,string> &reglist) const

{
  reglist = varnode_xref;
}

void SleighBase::getUserOpNames(vector<string> &res) const

{
  res = userop;		// Return list of all language defined user ops (with index)
}

/// This does the bulk of the work of creating a .sla file
/// \param s is the output stream
void SleighBase::saveXml(ostream &s) const

{
  s << "<sleigh";
  a_v_i(s,"version",SLA_FORMAT_VERSION);
  a_v_b(s,"bigendian",isBigEndian());
  a_v_i(s,"align",alignment);
  a_v_u(s,"uniqbase",getUniqueBase());
  if (maxdelayslotbytes > 0)
    a_v_u(s,"maxdelay",maxdelayslotbytes);
  if (unique_allocatemask != 0)
    a_v_u(s,"uniqmask",unique_allocatemask);
  if (numSections != 0)
    a_v_u(s,"numsections",numSections);
  s << ">\n";

  s << "<spaces";
  a_v(s,"defaultspace",getDefaultCodeSpace()->getName());
  s << ">\n";
  for(int4 i=0;i<numSpaces();++i) {
    AddrSpace *spc = getSpace(i);
    if (spc == (AddrSpace *)0) continue;
    if ((spc->getType()==IPTR_CONSTANT) || 
	(spc->getType()==IPTR_FSPEC)||
	(spc->getType()==IPTR_IOP)||
	(spc->getType()==IPTR_JOIN))
      continue;
    spc->saveXml(s);
  }
  s << "</spaces>\n";
  symtab.saveXml(s);
  s << "</sleigh>\n";
}

/// This parses the main \<sleigh> tag (from a .sla file), which includes the description
/// of address spaces and the symbol table, with its associated decoding tables
/// \param el is the root XML element
void SleighBase::restoreXml(const Element *el)

{
  maxdelayslotbytes = 0;
  unique_allocatemask = 0;
  numSections = 0;
  int4 version = 0;
  setBigEndian(xml_readbool(el->getAttributeValue("bigendian")));
  {
    istringstream s(el->getAttributeValue("align"));
    s.unsetf(ios::dec | ios::hex | ios::oct);
    s >> alignment;
  }
  {
    istringstream s(el->getAttributeValue("uniqbase"));
    s.unsetf(ios::dec | ios::hex | ios::oct);
    uintm ubase;
    s >> ubase;
    setUniqueBase(ubase);
  }
  int4 numattr = el->getNumAttributes();
  for(int4 i=0;i<numattr;++i) {
    const string &attrname( el->getAttributeName(i) );
    if (attrname == "maxdelay") {
      istringstream s1(el->getAttributeValue(i));
      s1.unsetf(ios::dec | ios::hex | ios::oct);
      s1 >> maxdelayslotbytes;
    }
    else if (attrname == "uniqmask") {
      istringstream s2(el->getAttributeValue(i));
      s2.unsetf(ios::dec | ios::hex | ios::oct);
      s2 >> unique_allocatemask;
    }
    else if (attrname == "numsections") {
      istringstream s3(el->getAttributeValue(i));
      s3.unsetf(ios::dec | ios::hex | ios::oct);
      s3 >> numSections;
    }
    else if (attrname == "version") {
      istringstream s(el->getAttributeValue(i));
      s.unsetf(ios::dec | ios::hex | ios::oct);
      s >> version;
    }
  }
  if (version != SLA_FORMAT_VERSION)
    throw LowlevelError(".sla file has wrong format");
  const List &list(el->getChildren());
  List::const_iterator iter;
  iter = list.begin();
  while((*iter)->getName() == "floatformat") {
    floatformats.push_back(FloatFormat());
    floatformats.back().restoreXml(*iter);
    ++iter;
  }
  restoreXmlSpaces(*iter,this);
  iter++;
  symtab.restoreXml(*iter,this);
  root = (SubtableSymbol *)symtab.getGlobalScope()->findSymbol("instruction");
  vector<string> errorPairs;
  buildXrefs(errorPairs);
  if (!errorPairs.empty())
    throw SleighError("Duplicate register pairs");
}
