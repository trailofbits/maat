contract HelloWorld {

   string public message;

   constructor() {
      message = "Hello world!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!";
   }

   function update(string memory newMessage) public {
      message = newMessage;
   }
}