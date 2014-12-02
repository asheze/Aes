using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using hilcoe.securityCourse;

namespace hilcoe.securityCourse.Tests.AesIntegrationTests
{
    [TestClass]
    public class IntegrationTests
    {
        [TestMethod]
        public void Cipher128_EndToEndTest()
        {
            byte[] input = new byte[]{ 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13, 14, 14, 15, 15  };

            byte[] key = new byte[] { 0, 0, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8, 0, 9, 0, 10, 0, 11, 0, 12, 0, 13, 0, 14, 0, 15 };

            byte[] output = AES.Cipher(input, key);

            Assert.AreEqual(new byte[] { 6, 9, 12, 4, 14, 0, 13, 8, 6, 10, 7, 11, 0, 4, 3, 0, 13, 8, 12, 13, 11, 7, 8, 0, 7, 0, 11, 4, 12, 5, 5, 10 }, output);
        }

        [TestMethod]
        public void DecipherEndToEndTest()
        {
            byte[] input = { 6, 9, 12, 4, 14, 0, 13, 8, 6, 10, 7, 11, 0, 4, 3, 0, 13, 8, 12, 13, 11, 7, 8, 0, 7, 0, 11, 4, 12, 5, 5, 10 };

            byte[] key = new byte[] { 0, 0, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8, 0, 9, 0, 10, 0, 11, 0, 12, 0, 13, 0, 14, 0, 15 };

            byte[] output = AES.Decipher(input, key);

            Assert.AreEqual(new byte[] { 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13, 14, 14, 15, 15 }, output);
        }
    }
}
