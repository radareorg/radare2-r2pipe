using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace r2pipe
{
    public class R2Command
    {
        #region Fields

        /// <summary>
        /// Gets or sets the callback.
        /// </summary>
        /// <value>
        /// The callback.
        /// </value>
        public Action<string> Callback { get; set; }

        /// <summary>
        /// Gets or sets the command.
        /// </summary>
        /// <value>
        /// The command.
        /// </value>
        public string Command { get; set; }

        #endregion Fields

        #region Constructors

        /// <summary>
        /// Initializes a new instance of the <see cref="R2Command"/> class.
        /// </summary>
        /// <param name="cmd">The command.</param>
        /// <param name="cb">The cb.</param>
        public R2Command(string cmd, Action<string> cb)
        {
            this.Command = cmd;
            this.Callback = cb;
        }

        #endregion Constructors

        #region Methods

        /// <summary>
        /// Returns a <see cref="System.String" /> that represents this instance.
        /// </summary>
        /// <returns>
        /// A <see cref="System.String" /> that represents this instance.
        /// </returns>
        public override string ToString()
        {
            return Command;
        }

        #endregion Methods
    }
}
