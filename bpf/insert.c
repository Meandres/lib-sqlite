#include <bpf_helpers.h>

unsigned long routine_implem(void* mem, unsigned long mem_length){
  arguments* args = (arguments*)mem;
  Hash *pH = (Hash*)args->ptr1;
  char *pKey = (char*)args->ptr2;
  void *data = args->ptr3;
  unsigned int h;       // the hash of the key modulo hash table size
  HashElem *elem;       // Used to loop thru the element list
  HashElem *new_elem;   // New element added to the pH

  //assert( pH!=0 );
  //assert( pKey!=0 );
  elem = internal_findElementWithHash(pH,pKey,&h);
  if( elem->data ){
    void *old_data = elem->data;
    if( data==0 ){
      internal_removeElement(pH,elem);
    }else{
      elem->data = data;
      elem->pKey = pKey;
    }
    return (unsigned long)old_data;
  }
  if( data==0 ) return 0;
  new_elem = (HashElem*)internal_malloc( sizeof(HashElem) );
  if( new_elem==0 ) return (unsigned long)data;
  new_elem->pKey = pKey;
  new_elem->h = h;
  new_elem->data = data;
  pH->count++;
  if( pH->count>=5 && pH->count > 2*pH->htsize ){
    internal_rehash(pH, pH->count*3);
  }
  internal_insertElement(pH, pH->ht ? &pH->ht[new_elem->h % pH->htsize] : 0, new_elem);
  return 0;
}
