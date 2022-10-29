namespace SevenZip
{
	/// <summary>
	/// The exception that is thrown when an error in input stream occurs during decoding.
	/// </summary>
	class DataErrorException : Exception
	{
		public DataErrorException(): base("Data Error") { }
	}

	/// <summary>
	/// The exception that is thrown when the value of an argument is outside the allowable range.
	/// </summary>
	class InvalidParamException : Exception
	{
		public InvalidParamException(): base("Invalid Parameter") { }
	}

    interface ISetDecoderProperties
	{
		void SetDecoderProperties(byte[] properties);
	}
}
