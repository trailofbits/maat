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
#include "sleigh.hh"
#include "loadimage.hh"

PcodeCacher::PcodeCacher(void)

{
  // We aim to allocate this array only once
  uint4 maxsize = 600;
  poolstart = new VarnodeData[ maxsize ];
  endpool = poolstart + maxsize;
  curpool = poolstart;
}

PcodeCacher::~PcodeCacher(void)

{
  delete [] poolstart;
}

VarnodeData *PcodeCacher::expandPool(uint4 size)

{ // Expand the pool so that -size- more elements fit
  // Return pointer to first available element
  uint4 curmax = endpool - poolstart;
  uint4 cursize = curpool - poolstart;
  if (cursize + size <= curmax)
    return curpool;		// No expansion necessary
  uint4 increase = (cursize + size) - curmax;
  if (increase < 100)		// Increase by at least 100
    increase = 100;

  uint4 newsize = curmax + increase;

  VarnodeData *newpool = new VarnodeData[newsize];
  for(uint4 i=0;i<cursize;++i)
    newpool[i] = poolstart[i];	// Copy old data
  // Update references to the old pool
  for(uint4 i=0;i<issued.size();++i) {
    VarnodeData *outvar = issued[i].outvar;
    if (outvar != (VarnodeData *)0) {
      outvar = newpool + (outvar - poolstart);
      issued[i].outvar = outvar;
    }
    VarnodeData *invar = issued[i].invar;
    if (invar != (VarnodeData *)0) {
      invar = newpool + (invar - poolstart);
      issued[i].invar = invar;
    }
  }
  list<RelativeRecord>::iterator iter;
  for(iter=label_refs.begin();iter!=label_refs.end();++iter) {
    VarnodeData *ref = (*iter).dataptr;
    (*iter).dataptr = newpool + (ref - poolstart);
  }
  
  delete [] poolstart;		// Free up old pool
  poolstart = newpool;
  curpool = newpool + (cursize + size);
  endpool = newpool + newsize;
  return newpool + cursize;
}

void PcodeCacher::addLabelRef(VarnodeData *ptr)

{ // Store off a reference to a label and the next instruction
  // address
  label_refs.push_back(RelativeRecord());
  label_refs.back().dataptr = ptr;
  label_refs.back().calling_index = issued.size();
}

void PcodeCacher::addLabel(uint4 id)

{ // Attach a label to the address of the next instruction
  while(labels.size() <= id)
    labels.push_back(0xbadbeef);
  labels[ id ] = issued.size();
}

void PcodeCacher::clear(void)

{
  curpool = poolstart;
  issued.clear();
  label_refs.clear();
  labels.clear();
}

void PcodeCacher::resolveRelatives(void)

{ // Assuming all the PcodeData has been generated for an
  // instruction, go resolve any relative offsets and back
  // patch their value(s) into the PcodeData
  list<RelativeRecord>::const_iterator iter;
  for(iter=label_refs.begin();iter!=label_refs.end();++iter) {
    VarnodeData *ptr = (*iter).dataptr;
    uint4 id = ptr->offset;
    if ((id >= labels.size())||(labels[id] == 0xbadbeef))
      throw LowlevelError("Reference to non-existant sleigh label");
    // Calculate the relative index given the two absolute indices
    uintb res = labels[id] - (*iter).calling_index;
    res &= calc_mask( ptr->size );
    ptr->offset = res;
  }
}

void PcodeCacher::emit(const Address &addr,PcodeEmit *emt) const

{ // Emit any cached pcode
  vector<PcodeData>::const_iterator iter;

  for(iter=issued.begin();iter!=issued.end();++iter)
    emt->dump(addr,(*iter).opc,(*iter).outvar,(*iter).invar,(*iter).isize);
}

void SleighBuilder::generateLocation(const VarnodeTpl *vntpl,VarnodeData &vn)

{				// Generate a concrete varnode -vn- from the template -vntpl-
  vn.space = vntpl->getSpace().fixSpace(*walker);
  vn.size = vntpl->getSize().fix(*walker);
  if (vn.space == const_space)
    vn.offset = vntpl->getOffset().fix(*walker) & calc_mask(vn.size);
  else if (vn.space == uniq_space) {
    vn.offset = vntpl->getOffset().fix(*walker);
    vn.offset |= uniqueoffset;
  }
  else
    vn.offset = vn.space->wrapOffset(vntpl->getOffset().fix(*walker));
}

AddrSpace *SleighBuilder::generatePointer(const VarnodeTpl *vntpl,VarnodeData &vn)

{				// Generate the pointer varnode -vn- from a dynamic template -vntpl-
  const FixedHandle &hand(walker->getFixedHandle(vntpl->getOffset().getHandleIndex()));
  vn.space = hand.offset_space;
  vn.size = hand.offset_size;
  if (vn.space == const_space)
    vn.offset = hand.offset_offset & calc_mask(vn.size);
  else if (vn.space == uniq_space)
    vn.offset = hand.offset_offset | uniqueoffset;
  else
    vn.offset = vn.space->wrapOffset(hand.offset_offset);
  return hand.space;
}

void SleighBuilder::dump(OpTpl *op)

{				// Dump on op through low-level dump interface
				// filling in dynamic loads and stores if necessary
  PcodeData *thisop;
  VarnodeData *invars;
  VarnodeData *loadvars;
  VarnodeData *storevars;
  VarnodeTpl *vn,*outvn;
  int4 isize = op->numInput();
				// First build all the inputs
  invars = cache->allocateVarnodes(isize);
  for(int4 i=0;i<isize;++i) {
    vn = op->getIn(i);
    if (vn->isDynamic(*walker)) {
      generateLocation(vn,invars[i]); // Input of -op- is really temporary storage
      PcodeData *load_op = cache->allocateInstruction();
      load_op->opc = CPUI_LOAD;
      load_op->outvar = invars + i;
      load_op->isize = 2;
      loadvars = load_op->invar = cache->allocateVarnodes(2);
      AddrSpace *spc = generatePointer(vn,loadvars[1]);
      loadvars[0].space = const_space;
      loadvars[0].offset = (uintb)(uintp)spc;
      loadvars[0].size = sizeof(spc);
    }
    else
      generateLocation(vn,invars[i]);
  }
  if ((isize>0)&&(op->getIn(0)->isRelative())) {
    invars->offset += getLabelBase();
    cache->addLabelRef(invars);
  }
  thisop = cache->allocateInstruction();
  thisop->opc = op->getOpcode();
  thisop->invar = invars;
  thisop->isize = isize;
  outvn = op->getOut();
  if (outvn != (VarnodeTpl *)0) {
    if (outvn->isDynamic(*walker)) {
      storevars = cache->allocateVarnodes(3);
      generateLocation(outvn,storevars[2]); // Output of -op- is really temporary storage
      thisop->outvar = storevars+2;
      PcodeData *store_op = cache->allocateInstruction();
      store_op->opc = CPUI_STORE;
      store_op->isize = 3;
      // store_op->outvar = (VarnodeData *)0;
      store_op->invar = storevars;
      AddrSpace *spc = generatePointer(outvn,storevars[1]); // pointer
      storevars[0].space = const_space;
      storevars[0].offset = (uintb)(uintp)spc; // space in which to store
      storevars[0].size = sizeof(spc);
    }
    else {
      thisop->outvar = cache->allocateVarnodes(1);
      generateLocation(outvn,*thisop->outvar);
    }
  }
}

void SleighBuilder::buildEmpty(Constructor *ct,int4 secnum)

{ // Build a named p-code section of a constructor that contains only implied BUILD directives
  int4 numops = ct->getNumOperands();
  
  for(int4 i=0;i<numops;++i) {
    SubtableSymbol *sym = (SubtableSymbol *)ct->getOperand(i)->getDefiningSymbol();
    if (sym == (SubtableSymbol *)0) continue;
    if (sym->getType() != SleighSymbol::subtable_symbol) continue;

    walker->pushOperand(i);
    ConstructTpl *construct = walker->getConstructor()->getNamedTempl(secnum);
    if (construct == (ConstructTpl *)0)
      buildEmpty(walker->getConstructor(),secnum);
    else
      build(construct,secnum);
    walker->popOperand();
  }
}

void SleighBuilder::setUniqueOffset(const Address &addr)

{
  uniqueoffset = (addr.getOffset() & uniquemask)<<4;
}

SleighBuilder::SleighBuilder(ParserWalker *w,DisassemblyCache *dcache,PcodeCacher *pc,AddrSpace *cspc,
			     AddrSpace *uspc,uint4 umask)
  : PcodeBuilder(0)
{
  walker = w;
  discache = dcache;
  cache = pc;
  const_space = cspc;
  uniq_space = uspc;
  uniquemask = umask;
  uniqueoffset = (walker->getAddr().getOffset() & uniquemask)<<4;
}

void SleighBuilder::appendBuild(OpTpl *bld,int4 secnum)

{				// Append pcode for a particular build statement
  int4 index = bld->getIn(0)->getOffset().getReal(); // Recover operand index from build statement
				// Check if operand is a subtable
  SubtableSymbol *sym = (SubtableSymbol *)walker->getConstructor()->getOperand(index)->getDefiningSymbol();
  if ((sym==(SubtableSymbol *)0)||(sym->getType() != SleighSymbol::subtable_symbol)) return;
  
  walker->pushOperand(index);
  Constructor *ct = walker->getConstructor();
  if (secnum >=0) {
    ConstructTpl *construct = ct->getNamedTempl(secnum);
    if (construct == (ConstructTpl *)0)
      buildEmpty(ct,secnum);
    else
      build(construct,secnum);
  }
  else {
    ConstructTpl *construct = ct->getTempl();
    build(construct,-1);
  }
  walker->popOperand();
}

void SleighBuilder::delaySlot(OpTpl *op)

{				// Append pcode for an entire instruction (delay slot)
				// in the middle of the current instruction
  ParserWalker *tmp = walker;
  uintb olduniqueoffset = uniqueoffset;

  Address baseaddr = tmp->getAddr();
  int4 fallOffset = tmp->getLength();
  int4 delaySlotByteCnt = tmp->getParserContext()->getDelaySlot();
  int4 bytecount = 0;
  do {
    Address newaddr = baseaddr + fallOffset;
    setUniqueOffset(newaddr);
    const ParserContext *pos = discache->getParserContext(newaddr);
    if (pos->getParserState() != ParserContext::pcode)
      throw LowlevelError("Could not obtain cached delay slot instruction");
    int4 len = pos->getLength();

    ParserWalker newwalker( pos );
    walker = &newwalker;
    walker->baseState();
    build(walker->getConstructor()->getTempl(),-1); // Build the whole delay slot
    fallOffset += len;
    bytecount += len;
  } while(bytecount < delaySlotByteCnt);
  walker = tmp;			// Restore original context
  uniqueoffset = olduniqueoffset;
}

void SleighBuilder::setLabel(OpTpl *op)

{
  cache->addLabel( op->getIn(0)->getOffset().getReal()+getLabelBase() );
}

void SleighBuilder::appendCrossBuild(OpTpl *bld,int4 secnum)

{ // Weave in the p-code section from an instruction at another address
  // bld-param(0) contains the address of the instruction
  // bld-param(1) contains the section number
  if (secnum>=0)
    throw LowlevelError("CROSSBUILD directive within a named section");
  secnum = bld->getIn(1)->getOffset().getReal();
  VarnodeTpl *vn = bld->getIn(0);
  AddrSpace *spc = vn->getSpace().fixSpace(*walker);
  uintb addr = spc->wrapOffset( vn->getOffset().fix(*walker) );

  ParserWalker *tmp = walker;
  uintb olduniqueoffset = uniqueoffset;

  Address newaddr(spc,addr);
  setUniqueOffset(newaddr);
  const ParserContext *pos = discache->getParserContext( newaddr );
  if (pos->getParserState() != ParserContext::pcode)
    throw LowlevelError("Could not obtain cached crossbuild instruction");
  
  ParserWalker newwalker( pos, tmp->getParserContext() );
  walker = &newwalker;

  walker->baseState();
  Constructor *ct = walker->getConstructor();
  ConstructTpl *construct = ct->getNamedTempl(secnum);
  if (construct == (ConstructTpl *)0)
    buildEmpty(ct,secnum);
  else
    build(construct,secnum);
  walker = tmp;
  uniqueoffset = olduniqueoffset;
}

void DisassemblyCache::initialize(int4 min,int4 hashsize)

{
  minimumreuse = min;
  mask = hashsize-1;
  uintb masktest = coveringmask((uintb)mask);
  if (masktest != (uintb)mask)	// -hashsize- must be a power of 2
    throw LowlevelError("Bad windowsize for disassembly cache");
  list = new ParserContext *[minimumreuse];
  nextfree = 0;
  hashtable = new ParserContext *[hashsize];
  for(int4 i=0;i<minimumreuse;++i) {
    ParserContext *pos = new ParserContext(contextcache);
    pos->initialize(75,20,constspace);
    list[i] = pos;
  }
  ParserContext *pos = list[0];
  for(int4 i=0;i<hashsize;++i)
    hashtable[i] = pos;		// Make sure all hashtable positions point to a real ParserContext
}

void DisassemblyCache::free(void)

{
  for(int4 i=0;i<minimumreuse;++i)
    delete list[i];
  delete [] list;
  delete [] hashtable;
}

DisassemblyCache::DisassemblyCache(ContextCache *ccache,AddrSpace *cspace,int4 cachesize,int4 windowsize)

{
  contextcache = ccache;
  constspace = cspace;
  initialize(cachesize,windowsize);		// Set default settings for the cache
}

ParserContext *DisassemblyCache::getParserContext(const Address &addr)

{ // Return a (possibly cached) ParserContext that is associated with -addr-
  // If n different calls to this interface are made with n different Addresses, if
  //    n <= minimumreuse   AND
  //    all the addresses are within the windowsize (=mask+1)
  // then the cacher guarantees that you get all different ParserContext objects
  int4 hashindex = ((int4) addr.getOffset()) & mask;
  ParserContext *res = hashtable[ hashindex ];
  if (res->getAddr() == addr)
    return res;
  res = list[ nextfree ];
  nextfree += 1;		// Advance the circular index
  if (nextfree >= minimumreuse)
    nextfree = 0;
  res->setAddr(addr);
  res->setParserState(ParserContext::uninitialized);	// Need to start over with parsing
  hashtable[ hashindex ] = res;	// Stick it into the hashtable
  return res;
}

Sleigh::Sleigh(LoadImage *ld,ContextDatabase *c_db)
  : SleighBase()

{
  loader = ld;
  context_db = c_db;
  cache = new ContextCache(c_db);
  discache = (DisassemblyCache *)0;
}

void Sleigh::clearForDelete(void)

{
  delete cache;
  if (discache != (DisassemblyCache *)0)
    delete discache;
}

Sleigh::~Sleigh(void)

{
  clearForDelete();
}

void Sleigh::reset(LoadImage *ld,ContextDatabase *c_db)

{ // Completely clear everything except the base and reconstruct
  // with a new loader and context
  clearForDelete();
  pcode_cache.clear();
  loader = ld;
  context_db = c_db;
  cache = new ContextCache(c_db);
  discache = (DisassemblyCache *)0;
}

void Sleigh::initialize(DocumentStorage &store)

{
  if (!isInitialized()) {	// Initialize the base if not already
    const Element *el = store.getTag("sleigh");
    if (el == (const Element *)0)
      throw LowlevelError("Could not find sleigh tag");
    restoreXml(el);
  }
  else
    reregisterContext();
  uint4 parser_cachesize = 2;
  uint4 parser_windowsize = 32;
  if ((maxdelayslotbytes > 1)||(unique_allocatemask != 0)) {
    parser_cachesize = 8;
    parser_windowsize = 256;
  }
  discache = new DisassemblyCache(cache,getConstantSpace(),parser_cachesize,parser_windowsize);
}

ParserContext *Sleigh::obtainContext(const Address &addr,int4 state) const

{ // Obtain a ParserContext for the instruction at the given -addr-.  This may be cached.
  // Make sure parsing has proceeded to at least the given -state.
  ParserContext *pos = discache->getParserContext(addr);
  int4 curstate = pos->getParserState();
  if (curstate >= state)
    return pos;
  if (curstate == ParserContext::uninitialized) {
    resolve(*pos);
    if (state == ParserContext::disassembly)
      return pos;
  }
  // If we reach here,  state must be ParserContext::pcode
  resolveHandles(*pos);
  return pos;
}

void Sleigh::resolve(ParserContext &pos) const

{				// Resolve ALL the constructors involved in the
				// instruction at this address
  loader->loadFill(pos.getBuffer(),16,pos.getAddr());
  ParserWalkerChange walker(&pos);
  pos.deallocateState(walker);	// Clear the previous resolve and initialize the walker
  Constructor *ct,*subct;
  uint4 off;
  int4 oper,numoper;

  pos.setDelaySlot(0);
  walker.setOffset(0);		// Initial offset
  pos.clearCommits();		// Clear any old context commits
  pos.loadContext();		// Get context for current address
  ct = root->resolve(walker);	// Base constructor
  walker.setConstructor(ct);
  ct->applyContext(walker);
  while(walker.isState()) {
    ct = walker.getConstructor();
    oper = walker.getOperand();
    numoper = ct->getNumOperands();
    while(oper < numoper) {
      OperandSymbol *sym = ct->getOperand(oper);
      off = walker.getOffset(sym->getOffsetBase()) + sym->getRelativeOffset();
      pos.allocateOperand(oper,walker); // Descend into new operand and reserve space
      walker.setOffset(off);
      TripleSymbol *tsym = sym->getDefiningSymbol();
      if (tsym != (TripleSymbol *)0) {
	subct = tsym->resolve(walker);
	if (subct != (Constructor *)0) {
	  walker.setConstructor(subct);
	  subct->applyContext(walker);
	  break;
	}
      }
      walker.setCurrentLength(sym->getMinimumLength());
      walker.popOperand();
      oper += 1;
    }
    if (oper >= numoper) { // Finished processing constructor
      walker.calcCurrentLength(ct->getMinimumLength(),numoper);
      walker.popOperand();
				// Check for use of delayslot
      ConstructTpl *templ = ct->getTempl();
      if ((templ != (ConstructTpl *)0)&&(templ->delaySlot() > 0))
	pos.setDelaySlot(templ->delaySlot());
    }
  }
  pos.setNaddr(pos.getAddr()+pos.getLength());	// Update Naddr to pointer after instruction
  pos.setParserState(ParserContext::disassembly);
}

void Sleigh::resolveHandles(ParserContext &pos) const

{				// Resolve handles (assuming Constructors already resolved)
  TripleSymbol *triple;
  Constructor *ct;
  int4 oper,numoper;

  ParserWalker walker(&pos);
  walker.baseState();
  while(walker.isState()) {
    ct = walker.getConstructor();
    oper = walker.getOperand();
    numoper = ct->getNumOperands();
    while(oper < numoper) {
      OperandSymbol *sym = ct->getOperand(oper);
      walker.pushOperand(oper);	// Descend into node
      triple = sym->getDefiningSymbol();
      if (triple != (TripleSymbol *)0) {
	if (triple->getType() == SleighSymbol::subtable_symbol)
	  break;
	else			// Some other kind of symbol as an operand
	  triple->getFixedHandle(walker.getParentHandle(),walker);
      }
      else {			// Must be an expression
	PatternExpression *patexp = sym->getDefiningExpression();
	intb res = patexp->getValue(walker);
	FixedHandle &hand(walker.getParentHandle());
	hand.space = pos.getConstSpace(); // Result of expression is a constant
	hand.offset_space = (AddrSpace *)0;
	hand.offset_offset = (uintb)res;
	hand.size = 0;		// This size should not get used
      }
      walker.popOperand();
      oper += 1;
    }
    if (oper >= numoper) {	// Finished processing constructor
      ConstructTpl *templ = ct->getTempl();
      if (templ != (ConstructTpl *)0) {
	HandleTpl *res = templ->getResult();
	if (res != (HandleTpl *)0)	// Pop up handle to containing operand
	  res->fix(walker.getParentHandle(),walker);
	// If we need an indicator that the constructor exports nothing try
        // else
	//   walker.getParentHandle().setInvalid();
      }
      walker.popOperand();
    }
  }
  pos.setParserState(ParserContext::pcode);
}

int4 Sleigh::instructionLength(const Address &baseaddr) const

{
  ParserContext *pos = obtainContext(baseaddr,ParserContext::disassembly);
  return pos->getLength();
}

int4 Sleigh::printAssembly(AssemblyEmit &emit,const Address &baseaddr) const

{
  int4 sz;

  ParserContext *pos = obtainContext(baseaddr,ParserContext::disassembly);
  ParserWalker walker(pos);
  walker.baseState();
  
  Constructor *ct = walker.getConstructor();
  ostringstream mons;
  ct->printMnemonic(mons,walker);
  ostringstream body;
  ct->printBody(body,walker);
  emit.dump(baseaddr,mons.str(),body.str());
  sz = pos->getLength();
  return sz;
}

int4 Sleigh::oneInstruction(PcodeEmit &emit,const Address &baseaddr) const

{
  int4 fallOffset;
  if (alignment != 1) {
    if ((baseaddr.getOffset() % alignment)!=0) {
      ostringstream s;
      s << "Instruction address not aligned: " << baseaddr;
      throw UnimplError(s.str(),0);
    }
  }
  
  ParserContext *pos = obtainContext(baseaddr,ParserContext::pcode);
  pos->applyCommits();
  fallOffset = pos->getLength();
  
  if (pos->getDelaySlot()>0) {
    int4 bytecount = 0;
    do {
    // Do not pass pos->getNaddr() to obtainContext, as pos may have been previously cached and had naddr adjusted
      ParserContext *delaypos = obtainContext(pos->getAddr() + fallOffset,ParserContext::pcode);
      delaypos->applyCommits();
      int4 len = delaypos->getLength();
      fallOffset += len;
      bytecount += len;
    } while(bytecount < pos->getDelaySlot());
    pos->setNaddr(pos->getAddr()+fallOffset);
  }
  ParserWalker walker(pos);
  walker.baseState();
  pcode_cache.clear();
  SleighBuilder builder(&walker,discache,&pcode_cache,getConstantSpace(),getUniqueSpace(),unique_allocatemask);
  try {
    builder.build(walker.getConstructor()->getTempl(),-1);
    pcode_cache.resolveRelatives();
    pcode_cache.emit(baseaddr,&emit);
  } catch(UnimplError &err) {
    ostringstream s;
    s << "Instruction not implemented in pcode:\n ";
    ParserWalker *cur = builder.getCurrentWalker();
    cur->baseState();
    Constructor *ct = cur->getConstructor();
    cur->getAddr().printRaw(s);
    s << ": ";
    ct->printMnemonic(s,*cur);
    s << "  ";
    ct->printBody(s,*cur);
    err.explain = s.str();
    err.instruction_length = fallOffset;
    throw err;
  }
  return fallOffset;
}

void Sleigh::registerContext(const string &name,int4 sbit,int4 ebit)

{  // Inform translator of existence of context variable
  context_db->registerVariable(name,sbit,ebit);
}

void Sleigh::setContextDefault(const string &name,uintm val)

{
  context_db->setVariableDefault(name,val);
}

void Sleigh::allowContextSet(bool val) const

{
  cache->allowSet(val);
}
